// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package miner

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// BuildPayloadArgs contains the provided parameters for building payload.
// Check engine-api specification for more details.
// https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#payloadattributesv3
type BuildPayloadArgs struct {
	Parent       common.Hash           // The parent block to build payload on top
	Timestamp    uint64                // The provided timestamp of generated payload
	FeeRecipient common.Address        // The provided recipient address for collecting transaction fee
	Random       common.Hash           // The provided randomness value
	Withdrawals  types.Withdrawals     // The provided withdrawals
	BeaconRoot   *common.Hash          // The provided beaconRoot (Cancun)
	Version      engine.PayloadVersion // Versioning byte for payload id calculation.

	NoTxPool     bool                 // Optimism addition: option to disable tx pool contents from being included
	Transactions []*types.Transaction // Optimism addition: txs forced into the block via engine API
	GasLimit     *uint64              // Optimism addition: override gas limit of the block to build
}

// Id computes an 8-byte identifier by hashing the components of the payload arguments.
func (args *BuildPayloadArgs) Id() engine.PayloadID {
	// Hash
	hasher := sha256.New()
	hasher.Write(args.Parent[:])
	binary.Write(hasher, binary.BigEndian, args.Timestamp)
	hasher.Write(args.Random[:])
	hasher.Write(args.FeeRecipient[:])
	rlp.Encode(hasher, args.Withdrawals)
	if args.BeaconRoot != nil {
		hasher.Write(args.BeaconRoot[:])
	}

	if args.NoTxPool || len(args.Transactions) > 0 { // extend if extra payload attributes are used
		binary.Write(hasher, binary.BigEndian, args.NoTxPool)
		binary.Write(hasher, binary.BigEndian, uint64(len(args.Transactions)))
		for _, tx := range args.Transactions {
			h := tx.Hash()
			hasher.Write(h[:])
		}
	}
	if args.GasLimit != nil {
		binary.Write(hasher, binary.BigEndian, *args.GasLimit)
	}

	var out engine.PayloadID
	copy(out[:], hasher.Sum(nil)[:8])
	out[0] = byte(args.Version)
	return out
}

// Payload wraps the built payload(block waiting for sealing). According to the
// engine-api specification, EL should build the initial version of the payload
// which has an empty transaction set and then keep update it in order to maximize
// the revenue. Therefore, the empty-block here is always available and full-block
// will be set/updated afterwards.
type Payload struct {
	id       engine.PayloadID
	empty    *types.Block
	full     *types.Block
	sidecars []*types.BlobTxSidecar
	fullFees *big.Int
	stop     chan struct{}
	lock     sync.Mutex
	cond     *sync.Cond

	err       error
	stopOnce  sync.Once
	interrupt *atomic.Int32 // interrupt signal shared with worker
}

// newPayload initializes the payload object.
func newPayload(empty *types.Block, id engine.PayloadID) *Payload {
	payload := &Payload{
		id:    id,
		empty: empty,
		stop:  make(chan struct{}),

		interrupt: new(atomic.Int32),
	}
	log.Info("Starting work on payload", "id", payload.id)
	payload.cond = sync.NewCond(&payload.lock)
	return payload
}

var errInterruptedUpdate = errors.New("interrupted payload update")

// update updates the full-block with latest built version.
func (payload *Payload) update(r *newPayloadResult, elapsed time.Duration, postFuncs ...func()) {
	payload.lock.Lock()
	defer payload.lock.Unlock()

	select {
	case <-payload.stop:
		return // reject stale update
	default:
	}

	defer payload.cond.Broadcast() // fire signal for notifying any full block result

	if errors.Is(r.err, errInterruptedUpdate) {
		log.Debug("Ignoring interrupted payload update", "id", payload.id)
		return
	} else if r.err != nil {
		log.Warn("Error building payload update", "id", payload.id, "err", r.err)
		payload.err = r.err // record latest error
		return
	}
	log.Debug("New payload update", "id", payload.id, "elapsed", common.PrettyDuration(elapsed))

	// Ensure the newly provided full block has a higher transaction fee.
	// In post-merge stage, there is no uncle reward anymore and transaction
	// fee(apart from the mev revenue) is the only indicator for comparison.
	if payload.full == nil || r.fees.Cmp(payload.fullFees) > 0 {
		payload.full = r.block
		payload.fullFees = r.fees
		payload.sidecars = r.sidecars

		feesInEther := new(big.Float).Quo(new(big.Float).SetInt(r.fees), big.NewFloat(params.Ether))
		log.Info("Updated payload",
			"id", payload.id,
			"number", r.block.NumberU64(),
			"hash", r.block.Hash(),
			"txs", len(r.block.Transactions()),
			"withdrawals", len(r.block.Withdrawals()),
			"gas", r.block.GasUsed(),
			"fees", feesInEther,
			"root", r.block.Root(),
			"elapsed", common.PrettyDuration(elapsed),
		)

		for _, postFunc := range postFuncs {
			if postFunc != nil {
				postFunc()
			}
		}
		buildBlockTimer.Update(elapsed)
	}
}

// Resolve returns the latest built payload and also terminates the background
// thread for updating payload. It's safe to be called multiple times.
func (payload *Payload) Resolve() *engine.ExecutionPayloadEnvelope {
	return payload.resolve(false)
}

// ResolveEmpty is basically identical to Resolve, but it expects empty block only.
// It's only used in tests.
func (payload *Payload) ResolveEmpty() *engine.ExecutionPayloadEnvelope {
	payload.lock.Lock()
	defer payload.lock.Unlock()

	return engine.BlockToExecutableData(payload.empty, big.NewInt(0), nil)
}

// ResolveFull is basically identical to Resolve, but it expects full block only.
// Don't call Resolve until ResolveFull returns, otherwise it might block forever.
func (payload *Payload) ResolveFull() *engine.ExecutionPayloadEnvelope {
	return payload.resolve(true)
}

func (payload *Payload) WaitFull() {
	payload.lock.Lock()
	defer payload.lock.Unlock()
	payload.cond.Wait()
}

func (payload *Payload) resolve(onlyFull bool) *engine.ExecutionPayloadEnvelope {
	payload.lock.Lock()
	defer payload.lock.Unlock()

	// We interrupt any active building block to prevent it from adding more transactions,
	// and if it is an update, don't attempt to seal the block.
	payload.interruptBuilding()

	if payload.full == nil && (onlyFull || payload.empty == nil) {
		select {
		case <-payload.stop:
			return nil
		default:
		}
		// Wait the full payload construction. Note it might block
		// forever if Resolve is called in the meantime which
		// terminates the background construction process.
		start := time.Now()
		payload.cond.Wait()
		waitPayloadTimer.UpdateSince(start)
		log.Debug("waitPayloadTimer", "duration", common.PrettyDuration(time.Since(start)), "id", payload.id)
	}

	// Now we can signal the building routine to stop.
	payload.stopBuilding()

	if payload.full != nil {
		return engine.BlockToExecutableData(payload.full, payload.fullFees, payload.sidecars)
	} else if !onlyFull && payload.empty != nil {
		return engine.BlockToExecutableData(payload.empty, big.NewInt(0), nil)
	} else if err := payload.err; err != nil {
		log.Error("Error building any payload", "id", payload.id, "err", err)
	}
	return nil
}

// interruptBuilding sets an interrupt for a potentially ongoing
// block building process.
// This will prevent it from adding new transactions to the block, and if it is
// building an update, the block will also not be sealed, as we would discard
// the update anyways.
// interruptBuilding is safe to be called concurrently.
func (payload *Payload) interruptBuilding() {
	// Set the interrupt if not interrupted already.
	// It's ok if it has either already been interrupted by payload resolution earlier,
	// or by the timeout timer set to commitInterruptTimeout.
	if payload.interrupt.CompareAndSwap(commitInterruptNone, commitInterruptResolve) {
		log.Debug("Interrupted payload building.", "id", payload.id)
	} else {
		log.Debug("Payload building already interrupted.",
			"id", payload.id, "interrupt", payload.interrupt.Load())
	}
}

// stopBuilding signals to the block updating routine to stop. An ongoing payload
// building job will still complete. It can be interrupted to stop filling new
// transactions with interruptBuilding.
// stopBuilding is safe to be called concurrently.
func (payload *Payload) stopBuilding() {
	// Concurrent Resolve calls should only stop once.
	payload.stopOnce.Do(func() {
		log.Debug("Stop payload building.", "id", payload.id)
		close(payload.stop)
	})
}

// fix attempts to recover and repair the block and its associated data (such as MPT)
// either from the local blockchain or from peers.
//
// In most cases, the block can be recovered from the local node's data. However,
// there is a corner case where this may not be possible: If the sequencer
// broadcasts a block but the local node crashes before fully writing the block to its local
// storage, the local chain might be lagging behind by one block compared to peers.
// In such cases, we need to recover the missing block data from peers.
//
// The function first tries to recover the block using the local blockchain via the
// fixManager.RecoverFromLocal method. If local recovery fails (e.g., due to the node
// missing the block), it attempts to retrieve the block header from peers and triggers
//
// blockHash: The hash of the latest block that needs to be recovered and fixed.
func (w *worker) fix(blockHash common.Hash) error {
	log.Info("Fix operation started")

	// Try to recover from local data
	err := w.stateFixManager.RecoverFromLocal(w, blockHash)
	if err != nil {
		// Only proceed to peer recovery if the error is "block not found in local chain"
		if strings.Contains(err.Error(), "block not found") {
			log.Warn("Local recovery failed, trying to recover from peers", "err", err)

			// Try to recover from peers
			err = w.stateFixManager.RecoverFromPeer(blockHash)
			if err != nil {
				return err
			}
		} else {
			log.Error("Failed to recover from local data", "err", err)
			return err
		}
	}

	log.Info("Fix operation completed successfully")
	return nil
}

// buildPayload builds the payload according to the provided parameters.
func (w *worker) buildPayload(args *BuildPayloadArgs) (*Payload, error) {
	if args.NoTxPool { // don't start the background payload updating job if there is no tx pool to pull from
		// Build the initial version with no transaction included. It should be fast
		// enough to run. The empty payload can at least make sure there is something
		// to deliver for not missing slot.
		// In OP-Stack, the "empty" block is constructed from provided txs only, i.e. no tx-pool usage.
		emptyParams := &generateParams{
			timestamp:   args.Timestamp,
			forceTime:   true,
			parentHash:  args.Parent,
			coinbase:    args.FeeRecipient,
			random:      args.Random,
			withdrawals: args.Withdrawals,
			beaconRoot:  args.BeaconRoot,
			noTxs:       true,
			txs:         args.Transactions,
			gasLimit:    args.GasLimit,
		}
		start := time.Now()
		empty := w.getSealingBlock(emptyParams)
		if empty.err != nil {
			log.Error("Built empty payload error", "id", args.Id(), "error", empty.err)
			return nil, empty.err
		}
		log.Info("Built empty payload succeed", "id", args.Id(), "number", empty.block.NumberU64(), "hash", empty.block.Hash(), "elapsed", common.PrettyDuration(time.Since(start)))

		payload := newPayload(empty.block, args.Id())
		// make sure to make it appear as full, otherwise it will wait indefinitely for payload building to complete.
		payload.full = empty.block
		payload.fullFees = empty.fees
		payload.cond.Broadcast() // unblocks Resolve
		return payload, nil
	}

	fullParams := &generateParams{
		timestamp:   args.Timestamp,
		forceTime:   true,
		parentHash:  args.Parent,
		coinbase:    args.FeeRecipient,
		random:      args.Random,
		withdrawals: args.Withdrawals,
		beaconRoot:  args.BeaconRoot,
		noTxs:       false,
		txs:         args.Transactions,
		gasLimit:    args.GasLimit,
	}

	// Since we skip building the empty block when using the tx pool, we need to explicitly
	// validate the BuildPayloadArgs here.
	blockTime, err := w.validateParams(fullParams)
	if err != nil {
		return nil, err
	}

	//check state of parent block
	_, err = w.retrieveParentState(fullParams)
	if err != nil {
		log.Error("err here", err)
	}
	if err != nil && strings.Contains(err.Error(), "missing trie node") {
		log.Error("missing parent state when building block, try to fix...")
		// fix state data
		fixErr := w.StartStateFix(args.Id(), fullParams.parentHash)
		if fixErr != nil {
			log.Error("fix failed", "err", fixErr)
		}
		return nil, err
	}

	payload := newPayload(nil, args.Id())
	// set shared interrupt
	fullParams.interrupt = payload.interrupt

	// Spin up a routine for updating the payload in background. This strategy
	// can maximum the revenue for including transactions with highest fee.
	go func() {
		// Setup the timer for re-building the payload. The initial clock is kept
		// for triggering process immediately.
		timer := time.NewTimer(0)
		defer timer.Stop()

		start := time.Now()
		// Setup the timer for terminating the payload building process as determined
		// by validateParams.
		endTimer := time.NewTimer(blockTime)
		defer endTimer.Stop()

		timeout := time.Now().Add(blockTime)

		stopReason := "delivery"
		defer func() {
			log.Info("Stopping work on payload",
				"id", payload.id,
				"reason", stopReason,
				"elapsed", common.PrettyDuration(time.Since(start)))
		}()

		updatePayload := func() time.Duration {
			start := time.Now()
			// getSealingBlock is interrupted by shared interrupt
			r := w.getSealingBlock(fullParams)

			dur := time.Since(start)
			// update handles error case

			payload.update(r, dur, func() {
				w.cacheMiningBlock(r.block, r.env)
			})
			if r.err == nil {
				// after first successful pass, we're updating
				fullParams.isUpdate = true
			} else {
				log.Error("Failed to build full payload", "id", payload.id, "err", r.err)
			}
			timer.Reset(w.recommit)
			return dur
		}

		var lastDuration time.Duration
		for {
			select {
			case <-timer.C:
				// We have to prioritize the stop signal because the recommit timer
				// might have fired while stop also got closed.
				select {
				case <-payload.stop:
					return
				default:
				}
				// Assuming last payload building duration as lower bound for next one,
				// skip new update if we're too close to the timeout anyways.
				if lastDuration > 0 && time.Now().Add(lastDuration).After(timeout) {
					stopReason = "near-timeout"
					return
				}
				lastDuration = updatePayload()
			case <-payload.stop:
				return
			case <-endTimer.C:
				stopReason = "timeout"
				return
			}
		}
	}()
	return payload, nil
}

func (w *worker) cacheMiningBlock(block *types.Block, env *environment) {
	var (
		start    = time.Now()
		receipts = make([]*types.Receipt, len(env.receipts))
		logs     []*types.Log
		hash     = block.Hash()
	)
	for i, taskReceipt := range env.receipts {
		receipt := new(types.Receipt)
		receipts[i] = receipt
		*receipt = *taskReceipt

		// add block location fields
		receipt.BlockHash = hash
		receipt.BlockNumber = block.Number()
		receipt.TransactionIndex = uint(i)

		// Update the block hash in all logs since it is now available and not when the
		// receipt/log of individual transactions were created.
		receipt.Logs = make([]*types.Log, len(taskReceipt.Logs))
		for i, taskLog := range taskReceipt.Logs {
			log := new(types.Log)
			receipt.Logs[i] = log
			*log = *taskLog
			log.BlockHash = hash
		}
		logs = append(logs, receipt.Logs...)
	}

	w.chain.CacheMiningReceipts(hash, receipts)
	w.chain.CacheMiningTxLogs(hash, logs)
	w.chain.CacheMiningState(hash, env.state)

	log.Info("Successfully cached sealed new block", "number", block.Number(), "root", block.Root(), "hash", hash,
		"elapsed", common.PrettyDuration(time.Since(start)))
}

func (w *worker) retrieveParentState(genParams *generateParams) (state *state.StateDB, err error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	log.Info("retrieveParentState validate")
	// Find the parent block for sealing task
	parent := w.chain.CurrentBlock()
	if genParams.parentHash != (common.Hash{}) {
		block := w.chain.GetBlockByHash(genParams.parentHash)
		if block == nil {
			return nil, fmt.Errorf("missing parent")
		}
		parent = block.Header()
	}

	state, err = w.chain.StateAt(parent.Root)

	// If there is an error and Optimism is enabled in the chainConfig, allow reorg
	if err != nil && w.chainConfig.Optimism != nil {
		if historicalBackend, ok := w.eth.(BackendWithHistoricalState); ok {
			// Attempt to retrieve the historical state
			var release tracers.StateReleaseFunc
			parentBlock := w.eth.BlockChain().GetBlockByHash(parent.Hash())
			state, release, err = historicalBackend.StateAtBlock(
				context.Background(), parentBlock, ^uint64(0), nil, false, false,
			)

			// Copy the state and release the resources
			state = state.Copy()
			release()
		}
	}

	// Return the state and any error encountered
	if err != nil {
		return nil, err
	}
	return state, nil
}

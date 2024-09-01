package miner

import (
	"sync"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

// FixManager 负责管理 fix 的状态和通知机制
type FixManager struct {
	mutex           sync.Mutex
	isFixInProgress bool
	fixChannels     sync.Map // 用于存储 fix 状态和通知 channel
	listenerStarted sync.Map // 存储每个 payload ID 是否已经启动了监听协程
}

// StartFix 启动 fix 的 goroutine 并管理 fix 状态
func (fm *FixManager) StartFix(worker *worker, id engine.PayloadID, parentHash common.Hash) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if !fm.IsFixInProgress() {
		fm.isFixInProgress = true
		fixChan := make(chan struct{})
		fm.fixChannels.Store(id, fixChan)

		go func() {
			defer func() {
				fm.mutex.Lock()
				fm.isFixInProgress = false
				fm.mutex.Unlock()

				// 通知外层 fix 已完成
				if ch, ok := fm.fixChannels.Load(id); ok {
					close(ch.(chan struct{}))
				}
			}()
			worker.fix(parentHash) // 执行修复逻辑
		}()
	}
}

// ListenFixCompletion 监听 fix 完成的逻辑，避免重复启动 goroutine
func (fm *FixManager) ListenFixCompletion(worker *worker, id engine.PayloadID, payload *Payload, args *BuildPayloadArgs) {
	ch, exists := fm.fixChannels.Load(id)
	if !exists {
		log.Info("payload is not fixing or has been completed")
		return
	}

	// 检查是否已经启动了监听协程
	if _, listenerExists := fm.listenerStarted.LoadOrStore(id, true); listenerExists {
		log.Info("Listener already started for payload", "payload", id)
		return // 如果监听协程已经启动，直接返回
	}

	go func() {
		log.Info("start waiting")
		<-ch.(chan struct{}) // 等待 fix 结束
		log.Info("Fix completed, retrying payload update", "id", id)
		worker.retryPayloadUpdate(args, payload)
		fm.fixChannels.Delete(id)     // 删除 fixChannels 中的 id
		fm.listenerStarted.Delete(id) // 删除 listenerStarted 中的标记位
	}()
}

// 检查 fix 是否正在进行
func (fm *FixManager) IsFixInProgress() bool {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()
	return fm.isFixInProgress
}

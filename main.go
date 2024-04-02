package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// 区块结构
type Block struct {
	Index     int
	Timestamp string
	Data      string
	PrevHash  string
	Hash      string
	Nonce     int
}

// 区块链结构
type Blockchain struct {
	Chain []Block
}

type Node struct {
	ID     int
	IP     string
	Port   int
	Faulty bool // 是否故障节点
}

// 创建新块
func NewBlock(index int, data string, prevHash string) *Block {
	block := &Block{
		Index:     index,
		Timestamp: time.Now().String(),
		Data:      data,
		PrevHash:  prevHash,
		Hash:      "",
		Nonce:     0,
	}
	proofOfWork(block)
	return block
}

// 验证交易
func isValidTransaction(data string) bool {
	// 在这里添加您的交易验证逻辑
	// 此处为示例，简单地假设所有交易都是有效的
	return true
}

// 计算区块的哈希
func calculateHash(block *Block) string {
	record := fmt.Sprintf("%d%s%s%s%d", block.Index, block.Timestamp, block.Data, block.PrevHash, block.Nonce)
	hash := sha256.Sum256([]byte(record))
	return hex.EncodeToString(hash[:])
}

// 工作量证明
func proofOfWork(block *Block) {
	for {
		block.Hash = calculateHash(block)
		if block.Hash[:4] == "0000" {
			break
		} else {
			block.Nonce++
		}
	}
}

// 添加新块到区块链
func (bc *Blockchain) AddBlock(data string) bool {
	prevBlock := bc.Chain[len(bc.Chain)-1]
	newBlock := NewBlock(prevBlock.Index+1, data, prevBlock.Hash)

	// 验证交易
	if isValidTransaction(data) {
		bc.Chain = append(bc.Chain, *newBlock)
		return true
	} else {
		return false
	}
}

// 添加新块到区块链，并执行拜占庭容错共识算法
func (bc *Blockchain) AddBlockWithBFT(data string, nodes []Node) bool {
	prevBlock := bc.Chain[len(bc.Chain)-1]
	newBlock := NewBlock(prevBlock.Index+1, data, prevBlock.Hash)

	// 执行拜占庭容错共识算法
	if BFTConsensus(nodes, data) {
		bc.Chain = append(bc.Chain, *newBlock)
		return true
	} else {
		return false
	}
}

func BFTConsensus(nodes []Node, blockData string) bool {
	// 检查节点数是否达到拜占庭容错阈值
	faultyCount := 0
	for _, node := range nodes {
		if node.Faulty {
			faultyCount++
		}
	}
	if faultyCount >= len(nodes)/3 {
		// 超过了拜占庭容错阈值，无法达成一致
		return false
	}

	// 执行拜占庭容错共识算法
	// 在这里可以进行消息传递、投票、验证等操作
	// 这里只是一个简单的示例，实际实现需要更多的细节和复杂性

	// 模拟共识过程，假设所有非故障节点达成一致
	fmt.Println("Consensus reached among non-faulty nodes")
	return true
}

var nodes []Node // 全局变量，存储节点列表

// 处理新节点加入的请求
func handleNewNode(conn net.Conn, id int, ip string, port int) {
	defer conn.Close()

	// 创建新节点
	newNode := Node{
		ID:     id,
		IP:     ip,
		Port:   port,
		Faulty: false, // 默认情况下，新节点不是故障节点
	}

	// 将新节点添加到节点列表
	nodes = append(nodes, newNode)

	fmt.Printf("New node joined: ID=%d, IP=%s, Port=%d\n", id, ip, port)
}

// 处理客户端加入请求
func handleJoinRequest(conn net.Conn, ip string, port int) {
	// 为新节点分配一个唯一的 ID，可以根据实际情况进行处理
	newID := len(nodes) + 1

	// 处理新节点加入
	handleNewNode(conn, newID, ip, port)

	// 发送加入成功响应给客户端
	conn.Write([]byte("Join request successful\n"))

	// 循环读取客户端消息，直到连接断开
	for {
		_, err := conn.Read(make([]byte, 1024)) // 读取客户端的任意数据，如果读取到EOF，说明连接断开
		if err != nil {
			fmt.Println("Client disconnected:", err.Error())
			// 在这里处理客户端断连后的逻辑，例如从节点列表中移除断连的节点等
			break
		}
	}
}

// 处理客户端请求
func handleConnection(conn net.Conn, blockchain *Blockchain) {
	defer conn.Close()

	// 读取客户端消息
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
		return
	}
	clientMsg := string(buf[:n])
	// 解析客户端消息
	parts := strings.Split(clientMsg, "|")
	if len(parts) < 2 {
		fmt.Println("Invalid message from client:", clientMsg)
		return
	}

	// 根据客户端请求执行相应操作
	switch parts[0] {
	case "GetBlockchain":
		// 发送区块链给客户端
		chainInBytes, _ := json.Marshal(blockchain.Chain)
		conn.Write(chainInBytes)
	case "AddBlock":
		// 尝试添加新区块到区块链
		if blockchain.AddBlock(parts[1]) {
			conn.Write([]byte("Block added successfully\n"))
		} else {
			conn.Write([]byte("Invalid transaction\n"))
		}
	case "AddBlockWithBFT":
		// 尝试添加新区块到区块链，并执行拜占庭容错共识算法
		if blockchain.AddBlockWithBFT(parts[1], nodes) {
			conn.Write([]byte("Block added successfully\n"))
		} else {
			conn.Write([]byte("Consensus not reached, block rejected\n"))
		}
	case "Join":
		// 处理客户端加入请求
		var port, _ = strconv.ParseInt(parts[2], 10, 32)
		handleJoinRequest(conn, parts[1], int(port)) // 假设客户端发送的消息格式为 "Join|IP|Port"
	default:
		fmt.Println("Unknown message from client:", clientMsg)
	}
}

func NewGenesisBlock() *Block {
	return NewBlock(0, "Genesis Block", "")
}

// 创建初始区块链
func NewBlockchain() *Blockchain {
	return &Blockchain{[]Block{*NewGenesisBlock()}}
}

func main() {
	// 创建初始区块链
	blockchain := NewBlockchain()

	// 监听端口
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer listener.Close()
	fmt.Println("Server listening on :8080")

	// 初始化节点列表
	nodes = make([]Node, 0)

	// 接受客户端连接
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err.Error())
			return
		}
		go handleConnection(conn, blockchain)
	}
}

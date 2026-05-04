package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

/* Para isolar esses bits, usamos operadores bitwise:
** o Shift Right (>>) para mover os bits do topo para a base,
** e o AND (&) com a máscara 0x0F (que é 00001111 em binário)
** para "limpar" os bits que não queremos.
**/
func stringToNibbles(s string) []byte {
	var nibbles []byte
	for i := 0; i < len(s); i++ {
		b := s[i]
		high := b >> 4
		low := b & 0x0F
		if len(nibbles) == 0 {
			nibbles = []byte{high, low}
			continue
		}
		nibbles = append(nibbles, high, low)
	}

	return nibbles
}

func main() {
	args := os.Args[1:]
	fmt.Printf("Nibbleando %s", args[0])
	nibbles := stringToNibbles(args[0])
	fmt.Printf("%v\n", nibbles)
	
	s := "Pedro"
	b := []byte(s)
	
	// Preparamos o slice para receber os blocos de 16 bits
	chunks := make([]uint16, 0, len(b)/2)

	for i := 0; i < len(b); i += 2 {
		// Se sobrar apenas 1 byte no final (string ímpar)
		if i+1 == len(b) {
			// Tratamos o último byte (ex: colocando um zero na frente)
			chunks = append(chunks, uint16(b[i]) << 8)
			break
		}
		
		// Converte os 2 bytes atuais em um uint16 (BigEndian)
		valor := binary.BigEndian.Uint16(b[i : i+2])
		chunks = append(chunks, valor)
	}

	fmt.Printf("Pedaços de 16 bits: %v\n", chunks)

	var result string

	for _, chunk := range chunks {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, chunk) // Extrai os 2 bytes do uint16
		result += string(buf)
	}

	fmt.Println("String reconstruída:", result)
}

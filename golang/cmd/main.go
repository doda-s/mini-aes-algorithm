package main

import (
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
	fmt.Printf("%v", nibbles)
}

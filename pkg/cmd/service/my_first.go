package main

import (
	"fmt"
)

// Test comment
func main () {
	x := [5]int{10, 20, 30, 40, 50}
	var a [5]int 
	
	c :="First value" 
	
	a[2] = 7
	
	fmt.Println(a)
	fmt.Println(x)
	fmt.Println(c)
	
	c = "second value"
	fmt.Println(c)
	
}


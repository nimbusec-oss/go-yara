package yara

import (
	"strconv"
	"sync"
	"unsafe"
)

/*
The closure type stores (pointers to) arbitrary data, returning a
simple int. A pointer to this int may be passed through C code to
callback functions written in Go that can use it to access the data
without violating the rules for passing pointers through C code.

Concurrent access to the stored data is protected through a
sync.RWMutex.
*/
type closure struct {
	m map[uintptr]interface{}
	sync.RWMutex
}

func (c *closure) Put(elem interface{}) unsafe.Pointer {
	c.Lock()
	if c.m == nil {
		c.m = make(map[uintptr]interface{})
	}
	defer c.Unlock()

	var i uintptr
	for i = 0; ; i++ {
		_, ok := c.m[i]
		if !ok {
			c.m[i] = elem
			return unsafe.Pointer(i)
		}
	}
}

func (c *closure) Get(ptr unsafe.Pointer) interface{} {
	c.RLock()
	defer c.RUnlock()

	id := uintptr(ptr)
	if r, ok := c.m[id]; ok {
		return r
	}
	panic("get: element " + strconv.Itoa(int(id)) + " not found")
}

func (c *closure) Delete(ptr unsafe.Pointer) {
	c.Lock()
	defer c.Unlock()

	id := uintptr(ptr)
	if _, ok := c.m[id]; !ok {
		panic("delete: element " + strconv.Itoa(int(id)) + " not found")
	}
	delete(c.m, id)
}

var callbackData closure

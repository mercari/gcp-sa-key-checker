package main

import (
	"errors"
	"sync"
)

// Why isn't this in the standard library...?
func parllelMap[I any, O any](items []I, f func(I) (O, error)) ([]O, error) {
	res := make([]O, len(items))
	errs := make([]error, len(items))
	var wg sync.WaitGroup
	wg.Add(len(items))
	for i, item := range items {
		i := i
		item := item
		go func() {
			defer wg.Done()
			r, err := f(item)
			res[i] = r
			errs[i] = err
		}()
	}
	wg.Wait()

	final_err := errors.Join(errs...)
	if final_err != nil {
		return nil, final_err
	}

	return res, nil
}

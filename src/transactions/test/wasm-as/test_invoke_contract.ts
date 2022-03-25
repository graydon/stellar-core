import * as stellar from './stellar';

export function invoke(arg: stellar.Val): stellar.Val {
	var i = stellar.asI32(arg)
	i /= 2
	i += 4
	return stellar.asI32Val(i)
}

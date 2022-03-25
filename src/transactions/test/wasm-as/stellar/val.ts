import * as hostfns from './hostfns';

export type Val = u64;

const valObjVoid: u64 = 0;
const valObjBoolTrue: u64 = 1;
const valObjBoolFalse: u64 = 2;

type tag = u16;

const tagObject: tag = 0;
const tagU32: tag = 1;
const tagI32: tag = 2;
const tagSymbol: tag = 3;
const tagBitset: tag = 4;
const tagTimePt: tag = 5;
const tagStatus: tag = 6;

function valFromTagBody(t: tag, body: u64): Val {
    assert(t < 7);
    const rotated = rotl(body, 16);
    assert(rotated&0xffff != 0);
	return rotated | t;
}

function valTag(v: Val): tag {
    return v as tag;
}

function valBody(v: Val): u64 {
    return v >> 16;
}

export function log(v: Val): void {
    hostfns.log_value(v);
}

export function asI32(v: Val): i32 {
    const t = valTag(v);
    assert(t == tagI32);
    const b = valBody(v);
    const i = b as i32;
    assert(i == b);
    return i;
}

export function asU32(v: Val): u32 {
    const t = valTag(v);
    assert(t == tagU32);
    const b = valBody(v);
    const i = b as u32;
    assert(i == b);
    return i;
}

export function asI32Val(i: i32): Val {
    return valFromTagBody(tagI32, i);
}

export function asU32Val(i: u32): Val {
    return valFromTagBody(tagU32, i);
}

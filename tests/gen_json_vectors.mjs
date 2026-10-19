import { writeFileSync } from 'node:fs';

// 服务端签名覆盖 JSON.stringify(data) 的精确字节。
//
// 两套夹具分开存：
//   json_payload.txt   data 的原始文本，直接可扫描，无外层转义
//   json_envelope.txt  完整响应，data 在内部是转义过的字符串
//   json_expected.json 每个键对应的 JSON.stringify 产出，作为比对基准
const payload = {
  zeta: 1,
  alpha: 'x',
  nested: { b: [true, null, 1.5], a: 'quote\\"inside' },
  unicode: '中文与行分隔符',
  large: 9007199254740991,
  empty: {},
  list: [],
};

const data = JSON.stringify(payload);
const envelope = JSON.stringify({ code: 0, data, sig: 'cafe' });

const expected = {};
for (const [key, value] of Object.entries(payload))
  expected[key] = JSON.stringify(value);

writeFileSync('tests/fixtures/json_payload.txt', data);
writeFileSync('tests/fixtures/json_envelope.txt', envelope);
writeFileSync('tests/fixtures/json_expected.json', JSON.stringify({
  expected,
  integers: { zeta: payload.zeta, large: payload.large },
}, null, 2));

console.log('wrote json fixtures');

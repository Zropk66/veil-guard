import { hkdfSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';

// 与 evidence::Binder 的 info 构造逐字节一致：
// ikm = 卡密，salt = nonce，info = evidence ‖ domain
const cardKey = 'VEIL-CARD-0001';
const nonce = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const domain = 0x01;

const zeroEvidence = Buffer.alloc(64);
const boundEvidence = Buffer.alloc(64);
boundEvidence[0] = 0x01;

const derive = (evidence) =>
  Buffer.from(hkdfSync('sha256', Buffer.from(cardKey, 'utf8'), nonce,
                       Buffer.concat([evidence, Buffer.from([domain])]), 32));

// 与 license::derive_machine_key 的 info 构造一致：
// info = machineId ‖ domain
const machineId = Buffer.from('MACHINE-ABC-123', 'utf8');
const machineKey = (d) =>
  Buffer.from(hkdfSync('sha256', Buffer.from(cardKey, 'utf8'), nonce,
                       Buffer.concat([machineId, Buffer.from([d])]), 32));

writeFileSync('tests/vectors.json', JSON.stringify({
  cardKey,
  nonceHex: nonce.toString('hex'),
  domain,
  zeroEvidenceHex: zeroEvidence.toString('hex'),
  zeroEvidenceKeyHex: derive(zeroEvidence).toString('hex'),
  boundEvidenceHex: boundEvidence.toString('hex'),
  boundEvidenceKeyHex: derive(boundEvidence).toString('hex'),
  machineIdHex: machineId.toString('hex'),
  keystreamKeyHex: machineKey(0x01).toString('hex'),
  bindingKeyHex: machineKey(0x02).toString('hex'),
}, null, 2));

console.log('wrote tests/vectors.json');

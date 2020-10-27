import { Signer, utils } from 'ethers';

const {
  keccak256, hashMessage, arrayify, recoverAddress, recoverPublicKey, computePublicKey,
} = utils;

const keys: { [key: string]: string } = {};

export async function getSignerPublicKey(signer: Signer): Promise<string> {
  const address = await signer.getAddress();
  if (keys[address]) {
    return keys[address];
  }
  const hash = keccak256(address);
  const digest = hashMessage(arrayify(hash));

  const signatures = [
    await signer.signMessage(arrayify(hash)),
    await signer.signMessage(arrayify(digest)),
  ];

  // eslint-disable-next-line no-restricted-syntax
  for (const sig of signatures) {
    if (address === recoverAddress(digest, sig)) {
      const key = computePublicKey(recoverPublicKey(digest, sig), true).slice(2);
      keys[address] = key;
      return key;
    }
  }
  return '';
}

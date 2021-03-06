import { JsonRpcProvider } from 'ethers/providers';
import { ContractFactory, Contract } from 'ethers';
import { expect } from 'chai';

import {
  erc1056Build, createProxy, proxyFactoryBuild, multiproxyBuild,
} from '../../packages/proxyIdentity/src';
import {
  IClaimsUser, ClaimsUser,
} from '../../packages/did-registry/node_modules/@ew-did-registry/claims/src';
import { DIDDocumentFull } from '../../packages/claims/node_modules/@ew-did-registry/did-document/src';
import { Methods } from '../../packages/did-registry/node_modules/@ew-did-registry/did/src';
import { DidStore } from '../../packages/did-ipfs-store/src';
import { Operator } from '../../packages/did-ethr-resolver/src';

import { spawnIpfsDaemon, shutDownIpfsDaemon, getSettings } from '..';

const { abi: proxyFactoryAbi, bytecode: proxyFactoryBytecode } = proxyFactoryBuild;
const { ethrReg: { abi: erc1056Abi, bytecode: erc1056Bytecode } } = erc1056Build;
const { abi: multiProxyAbi, bytecode: multiProxyBytecode } = multiproxyBuild;

describe('Identities shared management with proxies', function () {
  this.timeout(0);

  const provider = new JsonRpcProvider('http://localhost:8544');

  const deployer = provider.getSigner(0);
  const bebat = provider.getSigner(1);
  const oem = provider.getSigner(2);
  const installer = provider.getSigner(3);
  const customer = provider.getSigner(4);

  let oemDid: string;
  let installerDid: string;

  let erc1056: Contract;
  let erc1155: Contract;
  let proxyFactory: Contract;

  const serial = '1';
  let device: Contract;

  let store: DidStore;

  let installerClaims: IClaimsUser;

  let installerDoc: DIDDocumentFull;
  let oemDoc: DIDDocumentFull;

  const claimData = {
    type: 'lithium',
    status: 'installed',
  };

  before(async () => {
    oemDid = `did:${Methods.Erc1056}:${await oem.getAddress()}`;
    installerDid = `did:${Methods.Erc1056}:${await installer.getAddress()}`;

    const erc1056Creator = new ContractFactory(erc1056Abi, erc1056Bytecode, deployer);
    erc1056 = await erc1056Creator.deploy();

    const erc1155Creator = new ContractFactory(multiProxyAbi, multiProxyBytecode, deployer);
    erc1155 = await erc1155Creator.deploy();

    const proxyFactoryCreator = new ContractFactory(proxyFactoryAbi, proxyFactoryBytecode, bebat);
    proxyFactory = await proxyFactoryCreator.deploy(erc1056.address, erc1155.address);

    store = new DidStore(await spawnIpfsDaemon());
    const resolverSettings = await getSettings([
      await oem.getAddress(), await installer.getAddress(), await customer.getAddress(),
    ]);

    oemDoc = new DIDDocumentFull(oemDid, new Operator(oem, resolverSettings));
    await oemDoc.create();

    installerDoc = new DIDDocumentFull(installerDid, new Operator(installer, resolverSettings));
    await installerDoc.create();

    installerClaims = new ClaimsUser(installer, installerDoc, store);
  });

  it('BEBAT creates proxy identity and becomes its owner', async () => {
    device = await createProxy(proxyFactory, serial);
    expect(await device.owner()).equal(await bebat.getAddress());
  });

  it('BEBAT transfers ownership to OEM', async () => {
    await device.connect(bebat).changeOwner(await oem.getAddress());
    expect(await device.owner()).equal(await oem.getAddress());
  });

  it('OEM updates Battery metadata', async () => {
    const uri = 'ipfs://123abc';
    await device.connect(oem).updateUri(uri);
    expect(await device.uri()).equal(uri);
  });

  it('OEM as the owner adds Installer to approved agents', async () => {
    await device.connect(oem).addApprovedAgent(await installer.getAddress());
    expect(
      await device.isApproved(await installer.getAddress()),
    )
      .true;
  });

  it('Installer publishes self-issued claim', async () => {
    const claim = await installerClaims.createPublicClaim(claimData);

    const claimUrl = await installerClaims.publishPublicClaim(claim, claimData);

    expect(await store.get(claimUrl)).equal(claim);
  });

  it('Installer adds customer to approved agents', async () => {
    await device.connect(installer).addApprovedAgent(await customer.getAddress());

    expect(await device.isApproved(await customer.getAddress())).true;
  });

  it('Approved customer can update metadata uri', async () => {
    const uri = 'ipfs://ipfs/123abc';
    await device.connect(customer).updateUri(uri);

    expect(await device.uri()).equal(uri);
  });

  after(async () => {
    await shutDownIpfsDaemon();
  });
});

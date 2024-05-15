import {
  KeyShare, VerifyingKey
} from "synedrion";

describe("KeyShare.newCentralized()", () => {
  it("creates shares", () => {
    const parties = [VerifyingKey.random(), VerifyingKey.random()];
    const shares = KeyShare.newCentralized(parties, undefined);
    expect(shares.length).toEqual(2);
    expect(shares[0]).toEqual(expect.any(KeyShare));
    expect(shares[1]).toEqual(expect.any(KeyShare));
  });
});

describe("KeyShare", () => {
  it("serializes", () => {
    const parties = [VerifyingKey.random(), VerifyingKey.random()];
    const shares = KeyShare.newCentralized(parties, undefined);
    expect(shares[0].toBytes()).toEqual(expect.any(Uint8Array));
  });
});

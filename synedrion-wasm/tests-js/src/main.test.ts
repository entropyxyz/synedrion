import {
  KeyShare,
} from "synedrion";

describe("KeyShare.newCentralized()", () => {
  it("creates shares", () => {
    const shares = KeyShare.newCentralized(2, undefined);
    expect(shares.length).toEqual(2);
    expect(shares[0]).toEqual(expect.any(KeyShare));
    expect(shares[1]).toEqual(expect.any(KeyShare));
  });
});

describe("KeyShare", () => {
  it("serializes", () => {
    const shares = KeyShare.newCentralized(2, undefined);
    expect(shares[0].toBytes()).toEqual(expect.any(Uint8Array));
  });
});

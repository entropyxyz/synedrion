import {
  makeKeyShares,
  KeyShare,
} from "synedrion";

describe("makeKeyShares", () => {
  it("creates shares", () => {
    const shares = makeKeyShares(2, undefined);
    expect(shares.length).toEqual(2);
    expect(shares[0]).toEqual(expect.any(KeyShare));
    expect(shares[1]).toEqual(expect.any(KeyShare));
  });
});

describe("KeyShare", () => {
  it("serializes", () => {
    const shares = makeKeyShares(2, undefined);
    expect(shares[0].toBytes()).toEqual(expect.any(Uint8Array));
  });
});

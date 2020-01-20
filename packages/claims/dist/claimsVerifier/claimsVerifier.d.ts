import { Claims } from '../claims';
import { IClaimsVerifier } from '../interface';
export declare class ClaimsVerifier extends Claims implements IClaimsVerifier {
    /**
     * Checks issuer signature on token
     *
     * @example
     * ```typescript
     * import { ClaimsVerifier } from '@ew-did-registry/claims';
     * import { Keys } from '@ew-did-registry/keys';
     *
     * const keys = new Keys();
     * const claims = new ClaimsVerifier(verifier);
     * const verified = claims.verifyPublicProof(issuedToken);
     * ```
     * @param { string } token containing proof data
     * @returns { boolean } whether the proof was succesfull
     */
    verifyPublicProof(token: string): Promise<boolean>;
    /**
    * Checks issuer signature on issued token and user signature on proof token
    * and verifies that proof and private data mathches to each other
    *
    * @example
    * ```typescript
    * import { ClaimsVerifier } from '@ew-did-registry/claims';
    * import { Keys } from '@ew-did-registry/keys';
    *
    * const keys = new Keys();
    * const claims = new ClaimsVerifier(verifier);
    * const verified = claims.verifyPrivateProof(proofToken, privateToken);
    * ```
    * @param { string } proofToken contains proof data
    * @param { string } privateToken contains private data
    * @returns { boolean } whether the proof was succesfull
    */
    verifyPrivateProof(proofToken: string, privateToken: string): Promise<boolean>;
}

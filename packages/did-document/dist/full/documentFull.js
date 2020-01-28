"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var lite_1 = require("../lite");
var DIDDocumentFull = /** @class */ (function (_super) {
    __extends(DIDDocumentFull, _super);
    function DIDDocumentFull(did, operator) {
        var _this = _super.call(this, did, operator) || this;
        _this._operator = operator;
        return _this;
    }
    /**
     * Creates new empty DID document
     *
     * @example
     * ```typescript
     *  import { DIDDocumentFull } from '@ew-did-registry/did-document';
     *
     *  const document = new DIDDocumentFull(did, operator);
     *  await document.create();
     * ```
     * @return { boolean }
     */
    DIDDocumentFull.prototype.create = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this._operator.create()];
            });
        });
    };
    /**
     * Deactivates DID document
     *
     * @example
     * ```typescript
     * import { DIDDocumentFull } from '@ew-did-registry/did-document';
     *
     * const document = new DIDDocumentFull(did, operator);
     * await document.create();
     * await document.update(didAttribute, updateData, validity);
     * await document.deactivate();
     * ```
     * @return { boolean }
     */
    DIDDocumentFull.prototype.deactivate = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this._operator.deactivate(this.did)];
            });
        });
    };
    /**
     * Updates attribute on the DID document
     *
     * @example
     * ```typescript
     * import { DIDDocumentFull } from '@ew-did-registry/did-document';
     * import { DIDAttribute, Algorithms, PubKeyTypes } from '@ew-did-registry/did-document';
     *
     * const document = new DIDDocumentFull(did, operator);
     * await document.create();
     * const didAttribute = DIDAttribute.PublicKey;
     * const validity = 5 * 60 * 1000;
     * await document.update(
     *  DIDAttribute.PublicKey,
     *  {
     *    type: PubKeyType.VerificationKey2018,
     *    algo: Algorithms.ED25519,
     *    encoding: Encoding.HEX,
     *    value: new Keys().publicKey,
     *  },
     *  validity,
     *  );
     * ```
     * @param { DIDAttribute } attribute
     * @param { IUpdateData } data
     * @param { number } validity - time in milliseconds during the attribujte will be valid
     * @return { boolean }
     */
    DIDDocumentFull.prototype.update = function (attribute, data, validity) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this._operator.update(this.did, attribute, data, validity)];
            });
        });
    };
    return DIDDocumentFull;
}(lite_1.DIDDocumentLite));
exports.default = DIDDocumentFull;
//# sourceMappingURL=documentFull.js.map
"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var CognitokenError = /** @class */ (function (_super) {
    __extends(CognitokenError, _super);
    function CognitokenError(type, message) {
        var _this = _super.call(this, message) || this;
        Object.setPrototypeOf(_this, CognitokenError.prototype);
        _this.type = type;
        Error.captureStackTrace(_this, _this.constructor);
        return _this;
    }
    return CognitokenError;
}(Error));
exports.CognitokenError = CognitokenError;

const crypto = require('crypto');

/**
 * 微信消息加解密、签名验证
 */
class WeChatMsgCrypto {
    /**
     * 配置项
     * @param options[appId]            开发者APPID
     * @param options[key]              开发者消息加解密Key
     * @param options[token]            开发者消息校验Token
     * @param options[timestamp]        推送消息timestamp参数值
     * @param options[nonce]            推送消息nonce参数值
     * @param options[msgSignature]     推送消息msg_signature参数值
     * @param options[encrypt]          推送消息待解密消息
     */
    constructor(options) {
        this.options = options;

        this.MSG_LENGTH_SIZE = 4           // 存放消息体尺寸的空间大小。单位：字节
        this.RANDOM_BYTES_SIZE = 16        // 随机数据的大小。单位：字节
        this.BLOCK_SIZE = 32               // 分块尺寸。单位：字节

        let password = Buffer.from(options.key + '=', 'base64');

        /**
         * 对称加解密配置
         * @type {{password: string, iv: string, algorithm: string}}
         */
        this.SYMMETRIC_CONFIG = {
            algorithm: 'aes-256-cbc',
            password,
            iv: password.slice(0, 16),
        }
    }

    /**
     * 消息签名验证
     * @returns {boolean}   验证结果
     */
    signVerify() {
        let {timestamp, nonce, encrypt, token, msgSignature} = this.options;

        let rawStr = [token, timestamp, nonce, encrypt].sort().join('');

        return crypto.createHash('sha1').update(rawStr).digest('hex') == msgSignature
    }

    /**
     * 解密消息
     * @returns {*}     返回xml格式数据
     */
    decode() {
        // 将 base64 编码的数据转成 buffer
        let encryptedMsgBuf = Buffer.from(this.options.encrypt, 'base64')

        // 创建解密器实例
        let decipher = crypto.createDecipheriv(this.SYMMETRIC_CONFIG.algorithm, this.SYMMETRIC_CONFIG.password, this.SYMMETRIC_CONFIG.iv);

        // 禁用默认的数据填充方式
        decipher.setAutoPadding(false);

        // 解密后的数据
        let decryptdBuf = Buffer.concat([decipher.update(encryptedMsgBuf), decipher.final()])

        // 去除填充的数据
        decryptdBuf = this.PKCS7Decode(decryptdBuf);

        // 根据指定偏移值，从 buffer 中读取消息体的大小，单位：字节
        let msgSize = decryptdBuf.readUInt32BE(this.RANDOM_BYTES_SIZE);
        // 消息体的起始位置

        let msgBufStartPos = this.RANDOM_BYTES_SIZE + this.MSG_LENGTH_SIZE;

        // 消息体的结束位置
        let msgBufEndPos = msgBufStartPos + msgSize;

        return decryptdBuf.slice(msgBufStartPos, msgBufEndPos).toString();
    }

    /**
     * 按 PKCS#7 的方式从填充过的数据中提取原数据
     * @param buf       待处理的数据
     * @returns {*}     提取数据
     */
    PKCS7Decode(buf) {
        let padSize = buf[buf.length - 1]                       // 最后1字节记录着填充的数据大小
        return buf.slice(0, buf.length - padSize)               // 提取原数据
    }
}

export default WeChatMsgCrypto;

/*  Gibberish-AES 
*		A lightweight Javascript Libray for OpenSSL compatible AES CBC encryption.
*
*		Author: Mark Percival
*		Email: mark@mpercival.com
*		Copyright: 	Mark Percival - http://mpercival.com 	2008
*								Josh Davis - http://www.josh-davis.org/ecmaScrypt	2007
*								Chris Veness - http://www.movable-type.co.uk/scripts/aes.html 2007
*								Michel I. Gallant - http://www.jensign.com/
*
*		License: MIT
*		Usage: Gibberish.encrypt("secret", "password", 256)
*		Outputs: AES Encrypted text encoded in Base64
*/


var GibberishAES = {

	Nr:14, /* Default to 256 Bit Encryption */
	Nb:4,
	Nk:8,
	Decrypt:false,

	enc_utf8:function(s)
	{
		try{return unescape(encodeURIComponent(s));}
		catch(e){throw 'Error on UTF-8 encode';}
	},

	dec_utf8:function(s)
	{
		try{return decodeURIComponent(escape(s));}
		catch(e){throw('Bad Key');}
	},

	padBlock:function(byteArr)
	{
		var array = [];
		if (byteArr.length < 16) {
			var cpad = 16 - byteArr.length;
			var array = [cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad];
		}
		for(var i = 0; i < byteArr.length; i++)
		{
			array[i] = byteArr[i]
		}
		return array;
	},

	block2s:function(block,lastBlock)
	{
		var string = '';
		if (lastBlock) {
			var padding = block[15];
			if (padding > 16){throw('Decryption error: Maybe bad key');}
			if (padding == 16){ return '';}
			for(var i=0; i < 16-padding; i++){string += String.fromCharCode(block[i]);}
		} else {
			for (i=0; i<16; i++){string += String.fromCharCode(block[i]);}
		}
		return string;
	},

	a2h:function(numArr)
	{
		var string = '';
		for (var i=0; i<numArr.length; i++) {
			string += (numArr[i] < 16 ? '0' : '') + numArr[i].toString(16);
		}
		return string;
	},

	h2a:function(s)
	{
		var ret = [];
		s.replace(/(..)/g,function(s){
			ret.push(parseInt(s,16));
		});
		return ret;
	},
	
	s2a:function(string) {
		var array = [];
		for(var i = 0; i < string.length; i++)
		{
			array[i] = string.charCodeAt(i);
		}
		return array;
	},

	size:function(newsize)
	{
		switch (newsize)
		{
			case 128:
				this.Nr = 10;
				this.Nk = 4;
				break;
			case 192:
				this.Nr = 12;
				this.Nk = 6;
				break;
			case 256:
				this.Nr = 14;
				this.Nk = 8;
				break;
			default:
				throw('Invalid Key Size Specified:' + newsize);
		}
	},
	
	randArr:function(num) {
		var result = []
		for (var i=0; i < num; i++) {
			result = result.concat(Math.floor(Math.random()*256));
		}
		return result;
	},
	
	openSSLKey:function(passwordArr, saltArr){
		// Number of rounds depends on the size of the AES in use
		// 3 rounds for 256
		//		2 rounds for the key, 1 for the IV
		// 2 rounds for 128
		//		1 round for the key, 1 round for the IV
		// 3 rounds for 192 since it's not evenly divided by 128 bits
		var rounds = this.Nr >= 12 ? 3 : 2 ;
		var key = [];
		var iv = [];
		var md5_hash = [];
		var result = [];
		data00 = passwordArr.concat(saltArr);
		md5_hash[0] = GibberishAES.Hash.MD5(data00);
		result = md5_hash[0];
		for (var i=1; i < rounds; i++) {
			md5_hash[i] = GibberishAES.Hash.MD5(md5_hash[i-1].concat(data00));
			result = result.concat(md5_hash[i]);
		}
		key = result.slice(0,4*this.Nk);
		iv = result.slice(4*this.Nk, 4*this.Nk+16);
		return {key:key, iv:iv};
	},
	
	encryptOpenSSL:function(string, pass){ // string, password in plaintext
		var salt = this.randArr(8);
		var pbe = this.openSSLKey(this.s2a(pass), salt);
		var key = pbe.key;
		var iv = pbe.iv;
		string = this.s2a(this.enc_utf8(string));
		var cipherBlocks = this.encrypt(string, key, iv);
		var saltBlock = [[83, 97, 108, 116, 101, 100, 95, 95].concat(salt)]; // Spells out 'Salted__'
		cipherBlocks = saltBlock.concat(cipherBlocks);
		return this.Base64.encode(cipherBlocks);
	},
	
	decryptOpenSSL:function(string, pass){ // string, password in plaintext
		var cryptArr = this.Base64.decode(string);
		var salt = cryptArr.slice(8,16);
		var pbe = this.openSSLKey(this.s2a(pass), salt);
		var key = pbe.key;
		var iv = pbe.iv;
		var cryptArr = cryptArr.slice(16,cryptArr.length) // Take off the Salted__ffeeddcc
		string =  this.decrypt(cryptArr, key, iv);
		return string;
	},

	encrypt:function(plaintext, key, iv){ // plaintext, key and iv as byte arrays
		key = this.expandKey(key);
		var numBlocks = Math.ceil(plaintext.length/16);
		var blocks = [];
		for (var i=0; i < numBlocks; i++) {
			blocks[i] = this.padBlock(plaintext.slice(i*16, i*16+16));
		}
		if (plaintext.length%16 === 0){
			blocks.push([16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16]); // CBC OpenSSL padding scheme
			numBlocks++;
		}
		var cipherBlocks = [];
		for (var i=0; i < blocks.length; i++) {
			blocks[i] = (i === 0) ? this.xorBlocks(blocks[i], iv) : this.xorBlocks(blocks[i], cipherBlocks[i-1]);
			cipherBlocks[i] = this.encryptBlock(blocks[i], key);
		}
		return cipherBlocks;
	},
	
	decrypt:function(cryptArr, key, iv){ //  cryptArr, key and iv as byte arrays
		key = this.expandKey(key);
		var numBlocks = cryptArr.length/16;
		var cipherBlocks = [];
		for (var i=0; i < numBlocks; i++) {
			cipherBlocks.push(cryptArr.slice(i*16, (i+1)*16));
		}
		var plainBlocks = [];
		for (var i=cipherBlocks.length-1; i >= 0; i--) {
			plainBlocks[i] = this.decryptBlock(cipherBlocks[i], key);
			plainBlocks[i] = (i === 0) ? this.xorBlocks(plainBlocks[i], iv) : this.xorBlocks(plainBlocks[i], cipherBlocks[i-1]);
		}
		var string = '';
		for (var i=0; i < numBlocks-1; i++) {
			string += this.block2s(plainBlocks[i]);
		}
		string += this.block2s(plainBlocks[i], true);
		return this.dec_utf8(string);
	},

	encryptBlock:function(block, words){
		this.Decrypt = false;
		var state = this.addRoundKey(block, words, 0);
		for (var round=1; round < (this.Nr + 1); round++) {
			state = this.subBytes(state);
			state = this.shiftRows(state);
			if (round < this.Nr) {state = this.mixColumns(state);} //last round? don't mixColumns
			state = this.addRoundKey(state, words, round);
		}

		return state;
	},

	decryptBlock:function(block, words){
		this.Decrypt = true;
		var state = this.addRoundKey(block, words, this.Nr);
		for (var round=this.Nr-1; round > -1; round--) {
			state = this.shiftRows(state);
			state = this.subBytes(state);
			state = this.addRoundKey(state, words, round);
			if (round > 0) {state = this.mixColumns(state);} //last round? don't mixColumns
		}

		return state;
	},

	subBytes:function(state){
		var S = this.Decrypt ? this.SBoxInv : this.SBox;
		var temp = [];
			for (var i = 0; i < 16; i++){
				temp[i] = S[state[i]];
			}
		return temp;
	},

	shiftRows:function(state){
		var temp = [];
		var shiftBy = this.Decrypt ? [0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3] : [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11];
			for (var i = 0; i < 16; i++) {
				temp[i] = state[shiftBy[i]];
			}
		return temp;
	},

	mixColumns:function(state)
	{
		var column = [];
		var temp = [];
		/* iterate over the 4 columns */
		for (var i = 0; i < 4; i++){
			column[i] = this.mixColumn([state[i*4+0],state[i*4+1],state[i*4+2],state[i*4+3]]);
		}
		for (var i = 0; i < 4; i++){
			temp.push(column[i][0],column[i][1],column[i][2],column[i][3]);
		}
		return temp;
	},

	// galois multipication of 1 column of the 4x4 matrix
	mixColumn:function(column)
	{
		var mult = [];
		if(this.Decrypt){
			mult = [14,9,13,11];
		} else {
			mult = [2,1,1,3];
		}
		var cpy = [];
		for(var i = 0; i < 4; i++) {cpy[i] = column[i];}

		column[0] = 	this.galois_multiplication(cpy[0],mult[0]) ^
				this.galois_multiplication(cpy[3],mult[1]) ^
				this.galois_multiplication(cpy[2],mult[2]) ^
				this.galois_multiplication(cpy[1],mult[3]);
		column[1] = 	this.galois_multiplication(cpy[1],mult[0]) ^
				this.galois_multiplication(cpy[0],mult[1]) ^
				this.galois_multiplication(cpy[3],mult[2]) ^
				this.galois_multiplication(cpy[2],mult[3]);
		column[2] = 	this.galois_multiplication(cpy[2],mult[0]) ^
				this.galois_multiplication(cpy[1],mult[1]) ^
				this.galois_multiplication(cpy[0],mult[2]) ^
				this.galois_multiplication(cpy[3],mult[3]);
		column[3] = 	this.galois_multiplication(cpy[3],mult[0]) ^
				this.galois_multiplication(cpy[2],mult[1]) ^
				this.galois_multiplication(cpy[1],mult[2]) ^
				this.galois_multiplication(cpy[0],mult[3]);
		return column;
	},

	galois_multiplication:function(a,b)
	{
		var p = 0;
		for(var counter = 0; counter < 8; counter++)
		{
			if((b & 1) == 1) {p ^= a;}
			if(p > 0x100) {p ^= 0x100;}
			var hi_bit_set = (a & 0x80); //keep p 8 bit
			a <<= 1;
			if(a > 0x100) {a ^= 0x100;} //keep a 8 bit
			if(hi_bit_set === 0x80) {a ^= 0x1b;}
			if(a > 0x100) {a ^= 0x100;} //keep a 8 bit
			b >>= 1;
			if(b > 0x100) {b ^= 0x100;} //keep b 8 bit
		}
		return p;
	},

	// mixColumns:function(s) {   // combine bytes of each col of state S [§5.1.3]
	//   for (var c=0; c<4; c++) {
	//     var a = [];  // 'a' is a copy of the current column from 's'
	//     var b = [];  // 'b' is a•{02} in GF(2^8)
	//     for (var r=0; r<4; r++) {
	//       a[r] = s[r][c];
	//       b[r] = s[r][c]&128 ? s[r][c]<<1 ^ 283 : s[r][c]<<1;
	//     }
	//     // a[n] ^ b[n] is a•{03} in GF(2^8)
	//     s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // 2*a0 + 3*a1 + a2 + a3
	//     s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 * 2*a1 + 3*a2 + a3
	//     s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + 2*a2 + 3*a3
	//     s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // 3*a0 + a1 + a2 + 2*a3
	//   }
	//   return s;
	// },

	addRoundKey:function(state, words, round){
		var temp = [];
		for (var i = 0; i < 16; i++){
			temp[i] = state[i] ^ words[round][i];
		}
		return temp;
	},

	xorBlocks:function(block1, block2){
		var temp = [];
		for (var i = 0; i < 16; i++){
			temp[i] = block1[i] ^ block2[i];
		}
		return temp;
	},

	expandKey:function(key) {
		// Expects a 1d number array
		var Nb = this.Nb;
		var Nr = this.Nr;
		var Nk = this.Nk;

	  var w = [];
	  var temp = [];

	  for (var i=0; i<Nk; i++) {
	    var r = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]];
			w[i] = r;
	  }

	  for (var i=Nk; i<(4*(Nr+1)); i++) {
	    w[i] = [];
	    for (var t=0; t<4; t++) {temp[t] = w[i-1][t];}
	    if (i % Nk === 0) {
	      temp = this.subWord(this.rotWord(temp));
	      temp[0] ^= this.Rcon[i/Nk-1];
	    } else if (Nk > 6 && i%Nk == 4) {
	      temp = this.subWord(temp);
	    }
	    for (var t=0; t<4; t++) {w[i][t] = w[i-Nk][t] ^ temp[t];}
	  }
		var flat = [];
		for (var i=0; i<(Nr+1); i++){
			flat[i]=[];
			for (var j=0; j<4; j++) {flat[i].push(w[i*4+j][0],w[i*4+j][1],w[i*4+j][2],w[i*4+j][3]);}
		}
	  return flat;
	},

	subWord:function(w) {    // apply SBox to 4-byte word w
	  for (var i=0; i<4; i++) {w[i] = this.SBox[w[i]];}
	  return w;
	},

	rotWord:function(w) {    // rotate 4-byte word w left by one byte
	  var tmp = w[0];
	  for (var i=0; i<4; i++) {w[i] = w[i+1];}
	  w[3] = tmp;
	  return w;
	},


	// S-box
	SBox: [
	 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171,
	118, 202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164,
	114, 192, 183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113,
	216,  49,  21,   4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226,
	235,  39, 178, 117,   9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214,
	179,  41, 227,  47, 132,  83, 209,   0, 237,  32, 252, 177,  91, 106, 203,
	190,  57,  74,  76,  88, 207, 208, 239, 170, 251,  67,  77,  51, 133,  69,
	249,   2, 127,  80,  60, 159, 168,  81, 163,  64, 143, 146, 157,  56, 245,
	188, 182, 218,  33,  16, 255, 243, 210, 205,  12,  19, 236,  95, 151,  68,
	23,  196, 167, 126,  61, 100,  93,  25, 115,  96, 129,  79, 220,  34,  42,
	144, 136,  70, 238, 184,  20, 222,  94,  11, 219, 224,  50,  58,  10,  73,
	  6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121, 231, 200,  55, 109,
	141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8, 186, 120,  37,
	 46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138, 112,  62,
	181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158, 225,
	248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
	140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,
	 22 ],

	// Precomputed lookup table for the inverse SBox
	SBoxInv: [
	 82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215,
	251, 124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222,
	233, 203,  84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66,
	250, 195,  78,   8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73,
	109, 139, 209,  37, 114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92,
	204,  93, 101, 182, 146, 108, 112,  72,  80, 253, 237, 185, 218,  94,  21,
	 70,  87, 167, 141, 157, 132, 144, 216, 171,   0, 140, 188, 211,  10, 247,
	228,  88,   5, 184, 179,  69,   6, 208,  44,  30, 143, 202,  63,  15,   2,
	193, 175, 189,   3,   1,  19, 138, 107,  58, 145,  17,  65,  79, 103, 220,
	234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116,  34, 231, 173,
	 53, 133, 226, 249,  55, 232,  28, 117, 223, 110,  71, 241,  26, 113,  29,
	 41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27, 252,  86,  62,  75,
	198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,  31, 221, 168,
	 51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95,  96,  81,
	127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239, 160,
	224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,
	 23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12,
	125 ],
	// Rijndael Rcon
	Rcon:[1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94,
	188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145]

};

GibberishAES.Hash = {
	
	MD5:function (numArr) {
	
	    function RotateLeft(lValue, iShiftBits) {
	        return (lValue<<iShiftBits) | (lValue>>>(32-iShiftBits));
	    }
	
	    function AddUnsigned(lX,lY) {
	        var lX4,lY4,lX8,lY8,lResult;
	        lX8 = (lX & 0x80000000);
	        lY8 = (lY & 0x80000000);
	        lX4 = (lX & 0x40000000);
	        lY4 = (lY & 0x40000000);
	        lResult = (lX & 0x3FFFFFFF)+(lY & 0x3FFFFFFF);
	        if (lX4 & lY4) {
	            return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
	        }
	        if (lX4 | lY4) {
	            if (lResult & 0x40000000) {
	                return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
	            } else {
	                return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
	            }
	        } else {
	            return (lResult ^ lX8 ^ lY8);
	        }
	     }
	
	     function F(x,y,z) { return (x & y) | ((~x) & z); }
	     function G(x,y,z) { return (x & z) | (y & (~z)); }
	     function H(x,y,z) { return (x ^ y ^ z); }
	    function I(x,y,z) { return (y ^ (x | (~z))); }
	
	    function FF(a,b,c,d,x,s,ac) {
	        a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
	        return AddUnsigned(RotateLeft(a, s), b);
	    };
	
	    function GG(a,b,c,d,x,s,ac) {
	        a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
	        return AddUnsigned(RotateLeft(a, s), b);
	    };
	
	    function HH(a,b,c,d,x,s,ac) {
	        a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
	        return AddUnsigned(RotateLeft(a, s), b);
	    };
	
	    function II(a,b,c,d,x,s,ac) {
	        a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
	        return AddUnsigned(RotateLeft(a, s), b);
	    };
	
	    function ConvertToWordArray(numArr) {
	        var lWordCount;
	        var lMessageLength = numArr.length;
	        var lNumberOfWords_temp1=lMessageLength + 8;
	        var lNumberOfWords_temp2=(lNumberOfWords_temp1-(lNumberOfWords_temp1 % 64))/64;
	        var lNumberOfWords = (lNumberOfWords_temp2+1)*16;
	        var lWordArray=Array(lNumberOfWords-1);
	        var lBytePosition = 0;
	        var lByteCount = 0;
	        while ( lByteCount < lMessageLength ) {
	            lWordCount = (lByteCount-(lByteCount % 4))/4;
	            lBytePosition = (lByteCount % 4)*8;
	            lWordArray[lWordCount] = (lWordArray[lWordCount] | (numArr[lByteCount]<<lBytePosition));
	            lByteCount++;
	        }
	        lWordCount = (lByteCount-(lByteCount % 4))/4;
	        lBytePosition = (lByteCount % 4)*8;
	        lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80<<lBytePosition);
	        lWordArray[lNumberOfWords-2] = lMessageLength<<3;
	        lWordArray[lNumberOfWords-1] = lMessageLength>>>29;
	        return lWordArray;
	    };
	
	    function WordToHex(lValue) {
	        var WordToHexValue="",WordToHexValue_temp="",lByte,lCount;
					var WordToHexArr = []
	        for (lCount = 0;lCount<=3;lCount++) {
	            lByte = (lValue>>>(lCount*8)) & 255;
							WordToHexArr = WordToHexArr.concat(lByte)
	            // WordToHexValue_temp = "0" + lByte.toString(16);
	            // WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length-2,2);
	   	        }
	        return WordToHexArr;
	    };
	
	    function Utf8Encode(string) {
	        string = string.replace(/\r\n/g,"\n");
	        var utftext = "";
	
	        for (var n = 0; n < string.length; n++) {
	
	            var c = string.charCodeAt(n);
	
	            if (c < 128) {
	                utftext += String.fromCharCode(c);
	            }
	            else if((c > 127) && (c < 2048)) {
	                utftext += String.fromCharCode((c >> 6) | 192);
	                utftext += String.fromCharCode((c & 63) | 128);
	            }
	            else {
	                utftext += String.fromCharCode((c >> 12) | 224);
	                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
	                utftext += String.fromCharCode((c & 63) | 128);
	            }
	
	        }
	
	        return utftext;
	    };
	
	    var x=Array();
	    var k,AA,BB,CC,DD,a,b,c,d;
	    var S11=7, S12=12, S13=17, S14=22;
	    var S21=5, S22=9 , S23=14, S24=20;
	    var S31=4, S32=11, S33=16, S34=23;
	    var S41=6, S42=10, S43=15, S44=21;
	
	    x = ConvertToWordArray(numArr);
	
	    a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;
	
	    for (k=0;k<x.length;k+=16) {
	        AA=a; BB=b; CC=c; DD=d;
	        a=FF(a,b,c,d,x[k+0], S11,0xD76AA478);
	        d=FF(d,a,b,c,x[k+1], S12,0xE8C7B756);
	        c=FF(c,d,a,b,x[k+2], S13,0x242070DB);
	        b=FF(b,c,d,a,x[k+3], S14,0xC1BDCEEE);
	        a=FF(a,b,c,d,x[k+4], S11,0xF57C0FAF);
	        d=FF(d,a,b,c,x[k+5], S12,0x4787C62A);
	        c=FF(c,d,a,b,x[k+6], S13,0xA8304613);
	        b=FF(b,c,d,a,x[k+7], S14,0xFD469501);
	        a=FF(a,b,c,d,x[k+8], S11,0x698098D8);
	        d=FF(d,a,b,c,x[k+9], S12,0x8B44F7AF);
	        c=FF(c,d,a,b,x[k+10],S13,0xFFFF5BB1);
	        b=FF(b,c,d,a,x[k+11],S14,0x895CD7BE);
	        a=FF(a,b,c,d,x[k+12],S11,0x6B901122);
	        d=FF(d,a,b,c,x[k+13],S12,0xFD987193);
	        c=FF(c,d,a,b,x[k+14],S13,0xA679438E);
	        b=FF(b,c,d,a,x[k+15],S14,0x49B40821);
	        a=GG(a,b,c,d,x[k+1], S21,0xF61E2562);
	        d=GG(d,a,b,c,x[k+6], S22,0xC040B340);
	        c=GG(c,d,a,b,x[k+11],S23,0x265E5A51);
	        b=GG(b,c,d,a,x[k+0], S24,0xE9B6C7AA);
	        a=GG(a,b,c,d,x[k+5], S21,0xD62F105D);
	        d=GG(d,a,b,c,x[k+10],S22,0x2441453);
	        c=GG(c,d,a,b,x[k+15],S23,0xD8A1E681);
	        b=GG(b,c,d,a,x[k+4], S24,0xE7D3FBC8);
	        a=GG(a,b,c,d,x[k+9], S21,0x21E1CDE6);
	        d=GG(d,a,b,c,x[k+14],S22,0xC33707D6);
	        c=GG(c,d,a,b,x[k+3], S23,0xF4D50D87);
	        b=GG(b,c,d,a,x[k+8], S24,0x455A14ED);
	        a=GG(a,b,c,d,x[k+13],S21,0xA9E3E905);
	        d=GG(d,a,b,c,x[k+2], S22,0xFCEFA3F8);
	        c=GG(c,d,a,b,x[k+7], S23,0x676F02D9);
	        b=GG(b,c,d,a,x[k+12],S24,0x8D2A4C8A);
	        a=HH(a,b,c,d,x[k+5], S31,0xFFFA3942);
	        d=HH(d,a,b,c,x[k+8], S32,0x8771F681);
	        c=HH(c,d,a,b,x[k+11],S33,0x6D9D6122);
	        b=HH(b,c,d,a,x[k+14],S34,0xFDE5380C);
	        a=HH(a,b,c,d,x[k+1], S31,0xA4BEEA44);
	        d=HH(d,a,b,c,x[k+4], S32,0x4BDECFA9);
	        c=HH(c,d,a,b,x[k+7], S33,0xF6BB4B60);
	        b=HH(b,c,d,a,x[k+10],S34,0xBEBFBC70);
	        a=HH(a,b,c,d,x[k+13],S31,0x289B7EC6);
	        d=HH(d,a,b,c,x[k+0], S32,0xEAA127FA);
	        c=HH(c,d,a,b,x[k+3], S33,0xD4EF3085);
	        b=HH(b,c,d,a,x[k+6], S34,0x4881D05);
	        a=HH(a,b,c,d,x[k+9], S31,0xD9D4D039);
	        d=HH(d,a,b,c,x[k+12],S32,0xE6DB99E5);
	        c=HH(c,d,a,b,x[k+15],S33,0x1FA27CF8);
	        b=HH(b,c,d,a,x[k+2], S34,0xC4AC5665);
	        a=II(a,b,c,d,x[k+0], S41,0xF4292244);
	        d=II(d,a,b,c,x[k+7], S42,0x432AFF97);
	        c=II(c,d,a,b,x[k+14],S43,0xAB9423A7);
	        b=II(b,c,d,a,x[k+5], S44,0xFC93A039);
	        a=II(a,b,c,d,x[k+12],S41,0x655B59C3);
	        d=II(d,a,b,c,x[k+3], S42,0x8F0CCC92);
	        c=II(c,d,a,b,x[k+10],S43,0xFFEFF47D);
	        b=II(b,c,d,a,x[k+1], S44,0x85845DD1);
	        a=II(a,b,c,d,x[k+8], S41,0x6FA87E4F);
	        d=II(d,a,b,c,x[k+15],S42,0xFE2CE6E0);
	        c=II(c,d,a,b,x[k+6], S43,0xA3014314);
	        b=II(b,c,d,a,x[k+13],S44,0x4E0811A1);
	        a=II(a,b,c,d,x[k+4], S41,0xF7537E82);
	        d=II(d,a,b,c,x[k+11],S42,0xBD3AF235);
	        c=II(c,d,a,b,x[k+2], S43,0x2AD7D2BB);
	        b=II(b,c,d,a,x[k+9], S44,0xEB86D391);
	        a=AddUnsigned(a,AA);
	        b=AddUnsigned(b,BB);
	        c=AddUnsigned(c,CC);
	        d=AddUnsigned(d,DD);
	    }
	
	    var temp = WordToHex(a).concat(WordToHex(b),WordToHex(c),WordToHex(d));
			return temp;
	}
};

GibberishAES.Base64 = {
// Takes a Nx16x1 byte array and converts it to Base64 
	
	chars: [
		'A','B','C','D','E','F','G','H',
		'I','J','K','L','M','N','O','P',
		'Q','R','S','T','U','V','W','X',
		'Y','Z','a','b','c','d','e','f',
		'g','h','i','j','k','l','m','n',
		'o','p','q','r','s','t','u','v',
		'w','x','y','z','0','1','2','3',
		'4','5','6','7','8','9','+','/'],
		
	encode:function(b, withBreaks){
		var flatArr = [];
		var b64 = '';
		totalChunks = Math.floor(b.length*16/3)
		for(var i=0; i<b.length*16; i++){
			flatArr.push(b[Math.floor(i/16)][i%16]);
		}
		for(var i=0; i<flatArr.length; i=i+3){
			b64 += this.chars[flatArr[i] >> 2];
	    b64 += this.chars[((flatArr[i] & 3) << 4) | (flatArr[i+1] >> 4)];
			if (!(flatArr[i+1]==null)) {
				b64 += this.chars[((flatArr[i+1] & 15) << 2) | (flatArr[i+2] >> 6)];
			} else { b64 += '='}
			if (!(flatArr[i+2]==null)) {
	    	b64 += this.chars[flatArr[i+2] & 63];
			} else { b64 += '='}
		}
		// OpenSSL is super particular about line breaks
		var broken_b64 = b64.slice(0,64) + '\n';
		for (var i=1; i<(Math.ceil(b64.length/64)); i++) {
			broken_b64 += b64.slice(i*64,i*64+64) + ( Math.ceil(b64.length/64) == i+1 ? '' :'\n');
		}
		return broken_b64
	},
	
	decode:function(string){
		string = string.replace(/\n/g, '');
		var flatArr = [];
		var c = [];
		var b = [];
		for(var i=0; i<string.length; i=i+4){
			c[0] = this.chars.indexOf(string.charAt(i));
	    c[1] = this.chars.indexOf(string.charAt(i+1));
	    c[2] = this.chars.indexOf(string.charAt(i+2));
	    c[3] = this.chars.indexOf(string.charAt(i+3));

	    b[0] = (c[0] << 2) | (c[1] >> 4);
	    b[1] = ((c[1] & 15) << 4) | (c[2] >> 2);
	    b[2] = ((c[2] & 3) << 6) | c[3];
			flatArr.push(b[0],b[1],b[2]);
	  }
	flatArr = flatArr.slice(0,flatArr.length-(flatArr.length%16));
	return flatArr;
	},
	
};
public with sharing class JwtVerifierServiceSH256
{
	@AuraEnabled(cacheable=false)
	public static Boolean verifyJwt(String jwt)
	{
		try
		{
			if(String.isBlank(jwt)){
				System.debug('err=jwt_empty');
				return false;
			}

			List<String> parts=jwt.split('\\.');
			if(parts.size()!=3){
				System.debug('err=parts_size val='+parts.size());
				return false;
			}

			String headerB64=parts[0];
			String payloadB64=parts[1];
			String sigB64=parts[2];

			String signingInput=headerB64+'.'+payloadB64;

			String headerJson=base64UrlDecode(headerB64).toString();
			System.debug('step=header_decoded json='+headerJson);
			if(String.isBlank(headerJson)){
				System.debug('err=header_decode_blank');
				return false;
			}

			Map<String,Object> header=(Map<String,Object>)JSON.deserializeUntyped(headerJson);
			if(header==null){
				System.debug('err=header_null');
				return false;
			}
			if(!header.containsKey('kid') || !header.containsKey('alg')){
				System.debug('err=missing_kid_or_alg header='+header);
				return false;
			}
			if(((String)header.get('alg'))!='RS256'){
				System.debug('err=alg_mismatch val='+(String)header.get('alg'));
				return false;
			}
			String kid=(String)header.get('kid');
			System.debug('step=header_ok kid='+kid);

			HttpRequest req=new HttpRequest();
			req.setMethod('GET');
			req.setEndpoint(AvyApiService.configMap.get('jwks'));
			HttpResponse res=new Http().send(req);
			System.debug('step=jwks_http status='+res.getStatusCode());
			if(res.getStatusCode()!=200){
				System.debug('err=jwks_http_failed body='+res.getBody());
				return false;
			}

			Map<String,Object> jwks=(Map<String,Object>)JSON.deserializeUntyped(res.getBody());
			if(jwks==null || !jwks.containsKey('keys')){
				System.debug('err=jwks_no_keys body='+res.getBody());
				return false;
			}
			List<Object> keys=(List<Object>)jwks.get('keys');
			System.debug('step=jwks_parsed count='+keys.size());

			Map<String,Object> selectedKey=null;
			for(Object ko:keys){
				Map<String,Object> k=(Map<String,Object>)ko;
				System.debug('step=jwks_iter kid='+k.get('kid'));
				if(((String)k.get('kid'))==kid){
					selectedKey=k;
					break;
				}
			}
			if(selectedKey==null){
				System.debug('err=no_matching_kid');
				return false;
			}
			if(!'RSA'.equals((String)selectedKey.get('kty'))){
				System.debug('err=kty_invalid val='+selectedKey.get('kty'));
				return false;
			}
			if(!'RS256'.equals((String)selectedKey.get('alg'))){
				System.debug('err=key_alg_invalid val='+selectedKey.get('alg'));
				return false;
			}

			String n=(String)selectedKey.get('n');
			String e=(String)selectedKey.get('e');
			System.debug('step=jwk_parts n_len='+(n==null ? -1 : n.length())+' e='+e);

			Blob modulus=base64UrlDecode(n);
			Blob exponent=base64UrlDecode(e);
			System.debug('step=decoded_ne mod_size='+modulus.size()+' exp_size='+exponent.size());

			Blob pkcs1=rsaPublicKeyPkcs1(modulus,exponent);
			Blob spki=subjectPublicKeyInfo(pkcs1);

			Blob signature=base64UrlDecode(sigB64);

			Boolean sigOk=Crypto.verify('RSA-SHA256',Blob.valueOf(signingInput),signature,spki);
			System.debug('step=verify sig_ok='+sigOk);
			if(!sigOk){
				System.debug('err=signature_invalid');
				return false;
			}

			String payloadJson=base64UrlDecode(payloadB64).toString();
			Map<String,Object> payload=(Map<String,Object>)JSON.deserializeUntyped(payloadJson);
			if(payload==null || !payload.containsKey('exp')){
				System.debug('err=payload_no_exp payload='+payloadJson);
				return false;
			}
			Long expSec=(Long)payload.get('exp');
			Long nowSec=Datetime.now().getTime()/1000;
			if(expSec<nowSec){
				System.debug('err=expired exp='+expSec+' now='+nowSec);
				return false;
			}

			return true;
		}
		catch(Exception ex)
		{
			System.debug(
				'err=exception'
				+' type='+ex.getTypeName()
				+' msg='+ex.getMessage()
				+' cause='+String.valueOf(ex.getCause())
				+' line='+ex.getLineNumber()
				+' trace='+ex.getStackTraceString()
			);
			return false;
		}
	}

	public static Blob base64UrlDecode(String s)
	{
		if(s==null){
			return Blob.valueOf('');
		}
		String t=s.replace('-','+').replace('_','/');
		Integer mod=Math.mod(t.length(),4);
		if(mod==2){
			t=t+'==';
		}else if(mod==3){
			t=t+'=';
		}else if(mod==1){
			t=t+'===';
		}
		return EncodingUtil.base64Decode(t);
	}

	public static Blob rsaPublicKeyPkcs1(Blob modulus,Blob exponent)
	{
		List<Integer> modBytes=toBytes(modulus);
		while(!modBytes.isEmpty() && modBytes[0]==0){
			modBytes.remove(0);
		}
		if(modBytes.isEmpty()){
			modBytes.add(0);
		}
		if(modBytes[0]>=128){
			modBytes.add(0,0);
		}
		Blob modBlob=fromBytes(modBytes);

		List<Integer> expBytes=toBytes(exponent);
		while(!expBytes.isEmpty() && expBytes[0]==0){
			expBytes.remove(0);
		}
		if(expBytes.isEmpty()){
			expBytes.add(1);
		}
		if(expBytes[0]>=128){
			expBytes.add(0,0);
		}
		Blob expBlob=fromBytes(expBytes);

		Blob modInt=derIntegerHexSafe(modBlob);
		Blob expInt=derIntegerHexSafe(expBlob);
		Blob seqBody=blobConcat(modInt,expInt);
		return derSequence(seqBody);
	}

	public static Blob subjectPublicKeyInfo(Blob pkcs1)
	{
		Blob alg=derSequence(blobConcat(derOidRSA(),derNull()));
		Blob bitStr=derBitString(pkcs1);
		Blob spkiBody=blobConcat(alg,bitStr);
		return derSequence(spkiBody);
	}

	public static Blob derIntegerHexSafe(Blob val)
	{
		String hex=EncodingUtil.convertToHex(val);
		if(hex==null){
			hex='';
		}
		if(Math.mod(hex.length(),2)!=0){
			hex='0'+hex;
		}
		if(hex==''){
			hex='00';
		}else{
			Integer first=0;
			if(hex.length()>=2){
				first=parseHexByte(hex.substring(0,2));
			}
			if(first>=128){
				hex='00'+hex;
			}
		}
		Blob body=EncodingUtil.convertFromHex(hex);
		return derTagLenValue(2,body);
	}

	public static Blob derNull()
	{
		return derTagLenValue(5,Blob.valueOf(''));
	}

	public static Blob derOidRSA()
	{
		List<Integer> b=new List<Integer>();
		b.add(42);
		b.add(134);
		b.add(72);
		b.add(134);
		b.add(247);
		b.add(13);
		b.add(1);
		b.add(1);
		b.add(1);
		Blob body=fromBytes(b);
		return derTagLenValue(6,body);
	}

	public static Blob derBitString(Blob val)
	{
		List<Integer> prefix=new List<Integer>();
		prefix.add(0);
		Blob body=blobConcat(fromBytes(prefix),val);
		return derTagLenValue(3,body);
	}

	public static Blob derSequence(Blob body)
	{
		return derTagLenValue(48,body);
	}

	public static Blob derTagLenValue(Integer tag, Blob body)
	{
		List<Integer> out=new List<Integer>();
		out.add(tag);
		out.addAll(encodeDerLength(body.size()));
		if(out.isEmpty()){
			return body;
		}
		String hex='';
		for(Integer v:out){
			if(v<0) v+=256;
			hex+=toHexByte(v);
		}
		Blob head=EncodingUtil.convertFromHex(hex);
		return blobConcat(head,body);
	}

    public static List<Integer> encodeDerLength(Integer len)
    {
        if(len==null || len<0){
            len=0;
        }
        List<Integer> out=new List<Integer>();
        if(len<128){
            out.add(len);
            return out;
        }
        List<Integer> tmp=new List<Integer>();
        Integer n=len;
        while(n>0){
            Integer b=n & 255;
            tmp.add(b);
            n=n>>8;
        }
        if(tmp.isEmpty()){
            tmp.add(0);
        }
        // build reversed copy
        List<Integer> rev=new List<Integer>();
        for(Integer i=tmp.size()-1;i>=0;i--){
            rev.add(tmp[i]);
        }
        out.add(128+rev.size());
        out.addAll(rev);
        return out;
    }

	public static List<Integer> toBytes(Blob b)
	{
		if(b==null){
			return new List<Integer>();
		}
		String hex=EncodingUtil.convertToHex(b);
		if(String.isBlank(hex)){
			return new List<Integer>();
		}
		List<Integer> out=new List<Integer>();
		for(Integer i=0;i<hex.length();i+=2){
			out.add(parseHexByte(hex.substring(i,i+2)));
		}
		return out;
	}

	public static Integer parseHexByte(String s)
	{
		String h='0123456789ABCDEF';
		String u=s.toUpperCase();
		Integer hi=h.indexOf(u.substring(0,1));
		Integer lo=h.indexOf(u.substring(1,2));
		return (hi*16)+lo;
	}

	public static String toHexByte(Integer v)
	{
		String h='0123456789ABCDEF';
		Integer hi=(v>>4) & 15;
		Integer lo=v & 15;
		return h.substring(hi,hi+1)+h.substring(lo,lo+1);
	}

	public static Blob fromBytes(List<Integer> bytes)
	{
		if(bytes==null || bytes.isEmpty()){
			return Blob.valueOf('');
		}
		String h='';
		for(Integer i=0;i<bytes.size();i++){
			Integer v=bytes[i];
			if(v==null){
				continue;
			}
			if(v<0){
				v=256+v;
			}
			h+=toHexByte(v);
		}
		if(String.isBlank(h)){
			return Blob.valueOf('');
		}
		return EncodingUtil.convertFromHex(h);
	}

	public static Blob blobConcat(Blob a,Blob b)
	{
		List<Integer> out=new List<Integer>();
		out.addAll(toBytes(a));
		out.addAll(toBytes(b));
		return fromBytes(out);
	}
}

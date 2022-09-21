pragma solidity >=0.5.10;
pragma experimental ABIEncoderV2;



library VerifySig{
  //公匙：0x60320b8a71bc314404ef7d194ad8cac0bee1e331
  //公鑰是用來算出來後對比看看是否一直一致的
  
  //sha3(msg): 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45 (web3.sha3("abc");)
  //這個是數據的哈希，驗證簽名時用到
  
  //簽名後的數據：0xf4128988cbe7df8315440adde412a8955f7f5ff9a5468a791433727f82717a6753bd71882079522207060b681fbd3f5623ee7ed66e33fc8e581f442acbcf6ab800
  //簽名後的數據，包含r,s，v三個內容
  
  //驗證簽名入口函數
  function decode(bytes memory signedString) public pure returns (bytes32 ,bytes32 ,uint8 ){
      //這是一個已經簽名的數據
     // bytes memory signedString =hex"f4128988cbe7df8315440adde412a8955f7f5ff9a5468a791433727f82717a6753bd71882079522207060b681fbd3f5623ee7ed66e33fc8e581f442acbcf6ab800";
  
      bytes32 r=bytesToBytes32(slice(signedString,0,32));
      bytes32 s=bytesToBytes32(slice(signedString,32,32));
      byte  _v=slice(signedString,64,1)[0];
      uint8 v = uint8(_v);
      return (r,s,v);
     // return ecrecoverDecode(r,s,v);
      
  }
    function verifySig(bytes32[] memory _message,bytes32 _hash,bytes32 _r,bytes32 _s,uint8 _v)public pure returns(address addr) {
        require(keccak256(abi.encodePacked(_message)) == _hash,"error");
    return ecrecover(_hash,_v,_r,_s);
    }
    
    
  
  //切片函數
  function slice(bytes memory data,uint start,uint len) public pure returns(bytes memory){
      bytes memory b=new bytes(len);
      for(uint i=0;i<len;i++){
          b[i]=data[i+start];
      }
      return b;
  }
  //使用ecrecover恢復出公鑰，後對比
  function ecrecoverDecode(bytes32 _hash,bytes32 r,bytes32 s, uint8 v) public  pure returns(address addr){
     // uint8 v=uint8(v1);
      addr=ecrecover(_hash, v, r, s);
  }
  //bytes轉換爲bytes32
  function bytesToBytes32(bytes memory source) public pure returns(bytes32 result){
      assembly{
          result :=mload(add(source,32))
      }
  }
}

contract Mycontract {
   
    struct Receipt{
        bytes  PK_R;
        address payable  P_adr;
        uint256  photos;
        string  indexValue;
        bytes  sigClient;
        uint256 reward;
        bytes PreviousHash;
        bytes sigSPO;
        
        
        
    }
    struct AuditingMessage{
        bytes32[] slice;
        bytes32[] kvpairs;
        bytes sigSPO;
    }




   
    bytes32 public roothash2 ;
    bytes32 PK_SPO ;
    address payable SPOadr = 0xDA47b7bB5005AC438bd65646595A8B6559A0C370 ;
                            
 
    
    // 將報酬及罰金打入合約
    function transferBondToContract() public payable {
        
    }
    //bytesToBytes32
    function bytesToBytes32(bytes memory source) internal pure returns (bytes32 result) {
    assembly {
        result := mload(add(source, 32))
    }
  }
    //計算pairlist hash是否跟nodehash相同
    function _evalPairListHashFromNode(bytes32[] memory kvpairs,bytes32 _nodeHash) internal pure returns(bool) {
    bytes32 _hash = sha256(abi.encodePacked(kvpairs));
    if (_nodeHash!=_hash) {
        return false;
    }else {    
        return true;
    }
    }
    //計算slice的roothash
    function evalRootHashFromSlice(bytes32[] memory _slice, bytes32 _rootHash) internal pure returns(bool){
        bytes32 digest;
        //uint sliceCallCount += 1;
        uint256 parentIndex;
        for(uint256 i=0;i<_slice.length-1;i+=2){
            digest=sha256(abi.encodePacked(_slice[i],_slice[i+1]));
            parentIndex += 2;
            if(digest != _slice[parentIndex] && digest != _slice[parentIndex+1]) {
                return false;
            }
          /*  parentIndex= i+2+(_index/2==1?0:_index/2)%2;
            digest=sha256(abi.encodePacked(_slice[i],_slice[i+1]));
            _index=_index/2;*/
        }
        return digest == _rootHash;
    }
    //檢查Receipt簽章
    function verifyRsig(Receipt memory _r) public pure  returns(bool) {
        address cspAddress = 0xDA47b7bB5005AC438bd65646595A8B6559A0C370;
        bytes32 receipthash = msghash(_r); 
        (bytes32 r, bytes32 s, uint8 v) = VerifySig.decode(_r.sigSPO);
   
        return cspAddress == ecrecover(receipthash,v,r,s);
    }
    //檢查AuditingMessage簽章
    function verifyAMsig(AuditingMessage memory _m) internal pure  returns(bool) {
        address cspAddress = 0xDA47b7bB5005AC438bd65646595A8B6559A0C370;
        bytes32 AMhash = auditingmessagehash(_m); 
        (bytes32 r, bytes32 s, uint8 v) = VerifySig.decode(_m.sigSPO);
    
        return cspAddress == ecrecover(AMhash,v,r,s);
    }
    function bytesToBytes32array(bytes[] memory source) internal pure returns (bytes32[] memory){
    uint a = source.length;
    bytes32[] memory result = new bytes32[](a);
    for(uint i =0;i<source.length;i++){
       result[i] = bytesToBytes32(source[i]);
    }
    
    return result;
    
  }
   function msghash(Receipt memory r ) internal pure returns(bytes32){
        bytes memory prefix = "\x19Ethereum Signed Message:\n";
        
        bytes memory msg1 = abi.encodePacked(r.PK_R,r.P_adr,r.photos,r.indexValue,r.sigClient,r.reward,r.PreviousHash);
        uint256 _len = msg1.length;
        uint256 len = _len *2 ;
        
        bytes memory _msg = abi.encodePacked(prefix,len,msg1);
        
        bytes32 hash = keccak256(_msg);
        
        return hash;
    }
    function auditingmessagehash(AuditingMessage memory m) public pure returns (bytes32){
        bytes memory prefix = "\x19Ethereum Signed Message:\n";
        
        bytes memory msg1 = abi.encodePacked(m.slice,m.kvpairs);
        uint256 _len = msg1.length;
        uint256 len = _len *2 ;
        
        bytes memory _msg = abi.encodePacked(prefix,len,msg1);
        
        bytes32 hash = keccak256(_msg);
        
        return hash;
    }

    //bytes[PK_R, , sigClient, PreviousHash,SigSPO]
    //string[photos, indexValue, reward,]
    function getReceipthash(Receipt memory r) internal pure returns (bytes32){
        bytes32 receipthash = sha256(abi.encodePacked(r.PK_R,r.P_adr,r.photos,r.indexValue,r.sigClient,r.reward,r.PreviousHash,r.sigSPO));
        return receipthash;
    }
 
    //上傳正確的Slice，驗證Roothash ，將報酬轉到photographer address
     function getReward(Receipt memory _r, AuditingMessage memory _m)  public payable {
        
        //檢查receipt簽章
        
        require(verifyRsig(_r),"receipt signature is failed !");
        //檢查AuditingMessage簽章
        
        require(verifyAMsig(_m),"auditingmessage signature is failed !");
        //確認Slice的roothash是否跟公告的roothash相同
        require((evalRootHashFromSlice(_m.slice,roothash2)),"roothash wrong");
      
        //確認key-value list 的hash值
        require((_evalPairListHashFromNode(_m.kvpairs,_m.slice[0]) || _evalPairListHashFromNode(_m.kvpairs,_m.slice[1])),"keyvalue pairs hash wrong");
        uint256 reward = _r.reward   ;
        _r.P_adr.transfer(reward);
        
        //lock = false;
        
          
            
        }
    //抗議申訴
    //receipt不在樹上 申訴
    function notexistObjection(Receipt memory _r, AuditingMessage memory _m)public payable {
        
        //require(msg.value > 1 ether,"not enough ether");
       bool roothashCheck = (evalRootHashFromSlice(_m.slice,roothash2));
       
        //檢查receipt簽章
        
        require(verifyRsig(_r),"receipt signature is failed !");
        //檢查AuditingMessage簽章
        
        require(verifyAMsig(_m),"auditingmessage signature is failed !");
        
        
        bool kvpairsCheck = (_evalPairListHashFromNode(_m.kvpairs,_m.slice[0]) || _evalPairListHashFromNode(_m.kvpairs,_m.slice[1]));
        
        bytes32 keyhash = sha256(abi.encodePacked(_r.indexValue));
        
        for(uint i =0;i<_m.kvpairs.length;i+=2){
            if (keyhash == _m.kvpairs[i]){
                break;
            }
            
        }
      
            
        if (!(roothashCheck && kvpairsCheck)){
        
            msg.sender.transfer(1 ether);
        }
        
        
    }
    //reward申訴
   function wrongRewardObjection(Receipt memory _r1,Receipt memory _r2,AuditingMessage memory _m1,AuditingMessage memory _m2) public payable {
        
        
      
        require(verifyRsig(_r1),"receipt signature1 is failed !");
        require(verifyRsig(_r2),"receipt signature2 is failed !");
        
        
        require(verifyAMsig(_m1),"auditingmessage1 signature is failed !");
        
        
        require(verifyAMsig(_m2),"auditingmessage2 signature is failed !");
        require(evalRootHashFromSlice(_m1.slice,roothash2),"roothash1 is failed");
        require(evalRootHashFromSlice(_m2.slice,roothash2),"roothash2 is failed");
        require(_evalPairListHashFromNode(_m1.kvpairs,_m1.slice[0])||_evalPairListHashFromNode(_m1.kvpairs,_m2.slice[1]),"kvpairs hash1 failed");
        require(_evalPairListHashFromNode(_m2.kvpairs,_m2.slice[0])||_evalPairListHashFromNode(_m2.kvpairs,_m2.slice[1]),"kvpairs hash2 failed");
       //require(msg.value > 1 ether,"not enough ether");
        //require(getReceipthash(_r1) == bytesToBytes32(_r2.PreviousHash),"PreviousHash wrong!");
        if(_r2.reward != _r1.reward + _r2.photos * 1){
            msg.sender.transfer(1 ether);
        }
        
    }
    //PreviousHash申訴
    function PreviousHashObjection(Receipt memory _r1,Receipt memory _r2,AuditingMessage memory _m1,AuditingMessage memory _m2) public payable {
        require(verifyRsig(_r1),"receipt signature1 is failed !");
        require(verifyRsig(_r2),"receipt signature2 is failed !");
        
        
        require(verifyAMsig(_m1),"auditingmessage1 signature is failed !");
        
        
        require(verifyAMsig(_m2),"auditingmessage2 signature is failed !");
        require(evalRootHashFromSlice(_m1.slice,roothash2),"roothash1 is failed");
        require(evalRootHashFromSlice(_m2.slice,roothash2),"roothash2 is failed");
        require(_evalPairListHashFromNode(_m1.kvpairs,_m1.slice[0])||_evalPairListHashFromNode(_m1.kvpairs,_m2.slice[1]),"kvpairs hash1 failed");
        require(_evalPairListHashFromNode(_m2.kvpairs,_m2.slice[0])||_evalPairListHashFromNode(_m2.kvpairs,_m2.slice[1]),"kvpairs hash2 failed");
        
        if(bytesToBytes32(_r1.PreviousHash) == bytesToBytes32(_r2.PreviousHash)){
            msg.sender.transfer(1 ether);
        }
    }
    //indexValue重複申訴
    function indexValue_duplicatedObjection(Receipt memory _r1,Receipt memory _r2,AuditingMessage memory _m1,AuditingMessage memory _m2) public payable {
         require(verifyRsig(_r1),"receipt signature1 is failed !");
        require(verifyRsig(_r2),"receipt signature2 is failed !");
        
        
        require(verifyAMsig(_m1),"auditingmessage1 signature is failed !");
        
        
        require(verifyAMsig(_m2),"auditingmessage2 signature is failed !");
        require(evalRootHashFromSlice(_m1.slice,roothash2),"roothash1 is failed");
        require(evalRootHashFromSlice(_m2.slice,roothash2),"roothash2 is failed");
        require(_evalPairListHashFromNode(_m1.kvpairs,_m1.slice[0])||_evalPairListHashFromNode(_m1.kvpairs,_m2.slice[1]),"kvpairs hash1 failed");
        require(_evalPairListHashFromNode(_m2.kvpairs,_m2.slice[0])||_evalPairListHashFromNode(_m2.kvpairs,_m2.slice[1]),"kvpairs hash2 failed");
        
         bytes32 hash_index1 = sha256(abi.encodePacked(_r1.indexValue));
         bytes32 hash_index2 = sha256(abi.encodePacked(_r2.indexValue));
         if (hash_index1 == hash_index2){
             msg.sender.transfer(1 ether);
         }
    }
    //key-value list receipt雜湊值記錄錯誤
    function wrongReceipthashObjection(Receipt memory _r,AuditingMessage memory _m) public payable{
       // require(msg.value > 1 ether,"not enough ether");
       require(verifyRsig(_r),"receipt signature is failed !");
        //檢查AuditingMessage簽章
        
        require(verifyAMsig(_m),"auditingmessage signature is failed !");

        require(_evalPairListHashFromNode(_m.kvpairs,_m.slice[0]) || _evalPairListHashFromNode(_m.kvpairs,_m.slice[1]),"kvpairs hash wrong");
        bytes32 indexValue_hash = sha256(abi.encodePacked(_r.indexValue));
        bytes32 receipt_hash = getReceipthash(_r);
        for (uint i=0;i<_m.kvpairs.length;i+=2){
            if(_m.kvpairs[i] == indexValue_hash){
                if(_m.kvpairs[i+1] != receipt_hash){
                    msg.sender.transfer(1 ether);
                    break;
                }
                
            }
        }
        
    }
    address payable[3] public PK_reward;
    uint PK_num = 0;
    event Right_audit(string op, address PK, uint blocknum);
    function Right() public payable  returns(bool){
        require(msg.sender.balance >= 0.01 ether && msg.value >= 0.01 ether,"Not enough 1 ether in this transtraction");
        if(PK_num < 3){
            if(PK_num == 0){
                PK_reward[0] = msg.sender;
                PK_num = 1;
                emit Right_audit("auditor1", msg.sender, block.number);
            }else if(PK_num == 1){
                PK_reward[1] = msg.sender;
                PK_num = 2;
                emit Right_audit("auditor2", msg.sender, block.number);
            }else if(PK_num == 2){
                PK_reward[2] = msg.sender;
                PK_num = 3;
                emit Right_audit("auditor3", msg.sender, block.number);
            }
        }else{
            revert("already have 3 people Audited");
        }
        
    }
    
    function _test(AuditingMessage memory r ) public pure returns (bytes32[] memory){
        return r.slice;
    }
    function _balance() public view  returns  (uint256){
        
        address  self = address(this);
        return self.balance;
    }
    
    function bytesarrayhash (bytes32[] memory bh) public pure returns (bytes32){
        return sha256(abi.encodePacked(bh));
    }
    function uploadRoothash(bytes32 _roothash) public   {
        roothash2 = _roothash;
    }
    function returnroothash() view public  returns  (bytes32){
        return roothash2;
    }


}
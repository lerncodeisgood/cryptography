import hashlib
import json
import binascii
from dotenv.main import load_dotenv
import sha3
from attributedict.collections import AttributeDict
import math
from utils import hashbyte,hashstring,hash_LnR,leafnodehash
from make_receipt import transfer_dbfile_to_receipt, transfer_gcsfile_to_receipt
import os
import dotenv
load_dotenv()
class tp_MerkleTree():
	def __init__ (self,N):
		self.N = N#樹高

		self.leafnode_row = [''] * (2 ** (N-1))#葉子節點的陣列


	#計算index
	def calLeafIndex(self,key):
		hash_string = hashstring(key)
		indexValue = bin(int(hash_string,16))[0:self.N]
		indexValue = int(indexValue,2)

		return indexValue
	#針對我的Receipt進行型態轉換
	def adjust(self,array):
		array[0] = bytes(array[0][2:],encoding='utf-8')
		array[1] = bytes(array[1][2:],encoding='utf-8')
		array[2] = binascii.hexlify(array[2].to_bytes(32,'big'))
		array[3] = binascii.hexlify(bytes(str(array[3]),encoding='utf-8'))
		array[4] = bytes(array[4][2:],encoding='utf')
		array[5] = binascii.b2a_hex(array[5].to_bytes(32,'big'))
		array[6] = bytes(array[6][2:],encoding='utf-8')
		array[7] = bytes(array[7][2:],encoding='utf-8')
		return array
	#取得receipt的雜湊值
	def receipthash(self,json_file):
		value_dict = json_file.values()
		result = []
		for value in value_dict:
			result.append((value))
		#result = self.adjust(result)
		msg = ''.join(result)
		receipt_hash = hashstring(msg)
		return receipt_hash
	#插入key-value pair到tree中
	def Insert(self,receipt):
		R_dict = receipt
		leafnode_row = self.leafnode_row
		index = self.calLeafIndex(str(R_dict['indexValue']))
		indexValue_hash = hashstring(str(R_dict['indexValue']))

		receipt_hash = (self.receipthash(R_dict))
		#receipt_hash = Hashlib.hashstring(str(R_dict))
		key_value_dict = {binascii.a2b_hex(indexValue_hash):binascii.a2b_hex(receipt_hash)}
		if leafnode_row[index] == '':
			leafnode_row[index] = key_value_dict

		else:
			leafnode_row[index][binascii.a2b_hex(indexValue_hash)] = binascii.a2b_hex(receipt_hash)
		return leafnode_row


	#算出樹每個節點的hash值，Node_hash[0]為root hash，其餘依此類推
	def get_node_hash(self,leafnode):
		node_list= [''] * len(leafnode)
		for i in range(0,len(leafnode)):
			if leafnode[i] != '':
				node_list[i] = leafnodehash(leafnode[i])
			else:
				node_list[i] = hashstring((leafnode[i]))


		X = 0
		node_list = list(reversed(node_list))

		L = len(node_list)
		while(L - X >= 2):
			L = len(node_list)
			for i in range(X,L,2):

				node_hash =hash_LnR(node_list[i+1],node_list[i])

				node_list.append(node_hash)
			X = L
			L = len(node_list)
		nodehash = list(reversed(node_list))
		return nodehash,nodehash[0]

	#取得leafnode節點編號為I的Slice
	def ExtractSlice(self,leafnode,I):
		nodehash = (self.get_node_hash(leafnode))[0]
		Slice = list()
		X = I + 2 ** (self.N-1)-1
		while(X != 0):
			if X % 2 == 0:

				Slice.append(nodehash[X-1])
				Slice.append(nodehash[X])
			else:
				Slice.append(nodehash[X])
				Slice.append(nodehash[X+1])


			X = (math.floor((X-1)/2))


		Slice.append(nodehash[0])
		Slice = ''.join(Slice)
		return Slice
	#計算取出的Slice算出的root hash值是否跟root hash相同
	def evalRootHashFromSlice(self,Slice,roothash):
		Slice = [Slice[i:i+64] for i in range(0,len(Slice), 64)]
		pt = 0 #pointer of slice
		while(pt<len(Slice)-3):
			digest = hash_LnR(Slice[pt],Slice[pt+1])
			if (digest != Slice[pt+2]) and (digest != Slice[pt+3]):
				print("Value Error")
				print("where happend : ",Slice.index(Slice[pt]))
			pt += 2
		digest = hash_LnR(Slice[pt],Slice[pt+1])

		return digest == roothash


if __name__ == '__main__':
	# tp_tree_db = tp_MerkleTree(3)
	# receipt_list = transfer_dbfile_to_receipt()
	# for r in receipt_list:
	# 	tp_tree_db.Insert(r)
	# leafnoderow_db = tp_tree_db.leafnode_row
	# rh_db = (tp_tree_db.get_node_hash(leafnoderow_db))[0]

	# tp_tree_gcs = tp_MerkleTree(16)
	# receipt_list = transfer_gcsfile_to_receipt(os.getenv('GCS_BUCKET'))
	# for r in receipt_list:
	# 	tp_tree_gcs.Insert(r)
	# leafnoderow_gcs = tp_tree_gcs.leafnode_row
	# rh_gcs = (tp_tree_gcs.get_node_hash(leafnoderow_gcs))[1]
	# index = tp_tree_gcs.calLeafIndex('6d7af00a-dde4-43b6-8308-27e4fe23f0f0.png')

	# sl = tp_tree_gcs.ExtractSlice(leafnoderow_gcs,index)

	# print(tp_tree_gcs.evalRootHashFromSlice(sl,rh_gcs))
	# print(rh_gcs)
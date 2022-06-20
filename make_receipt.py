import pymysql
import os
from google.cloud import storage
from dotenv import load_dotenv
load_dotenv()


def transfer_dbfile_to_receipt():
    conn = pymysql.connect(user='Nick',
                            host=os.getenv('MYSQL_HOST'),
                            port=3306,
                            password=os.getenv('MYSQL_PASSWORD'),
                            ssl_cert=os.getenv('MYSQL_CERT'),
                            ssl_ca=os.getenv('MYSQL_CA'),
                            ssl_key=os.getenv('MYSQL_KEY'))
    cursor = conn.cursor()
    cursor.execute(f"SELECT `uuid` FROM kangaroo.files_file")
    result = cursor.fetchall()
    receipt_list = []
    for uuid in result:
        receipt = {}
        receipt['indexValue'] = str(uuid[0])
        receipt_list.append(receipt)
    return receipt_list

def transfer_gcsfile_to_receipt(bucket_name):
    storage_client = storage.Client.from_service_account_json(os.getenv('GOOGLE_APPLICATION_CREDENTIALS'))
    list_of_blobs = storage_client.list_blobs(bucket_name)
    receipt_list = []
    for blob in list_of_blobs:
        receipt ={}
        receipt['indexValue'] = str(blob.name)
        receipt_list.append(receipt)
    return receipt_list

if __name__ == '__main__':
  r_db = (transfer_dbfile_to_receipt())
  r_gcs = transfer_gcsfile_to_receipt(os.getenv('GCS_BUCKET'))
  
  #print(r_db == r_gcs)
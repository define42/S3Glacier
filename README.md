# S3 Glacier Archive Server 
S3 Glacier is essentially a storage database with high write performance and cohesive delete performance.  
  
It's design is simple (~2000 line of code) and data is simply saved into Tar archives, identified by timestamp in the UUID. 

- UUID version 1(RFC 4122) include timestamp in the UUID and is supported without any changes. 
- UUID version 4 is supported by adding a human readable timestamp(`YYYYMMDD-HHMM`) in the first two sections. 

Timestamps identifies the exact location on disk by mapping the timestamp into a folder-age-tree (`/YYYY/MM/DD/HH/xx.tar`). Each subfolder (for each hours) contains 256 Tar archives where the last two UUIDv4 hex-values identify the archive it is associated. For UUIDv1 the Mid-time[4-5] defindes the Tar arhive the blob is associated. 
Splitting each hour into 256 Tar archives increases write performance by limiting write-lock to the same archive, and thereby 256 thread can write/read simultaniously in each hour section. 

`(A blob with Time-UUID "20211218-1036-40f1-b34f-02d7517a01d3" will be appended into "/2021/12/18/10/d3.tar")`

Pros
- Optimized for all blob sizes (1 byte to 8GB)
- Unlimited numbers of blobs
- High write performance
- The number of files on disk is always known(maximum 256 Tar archives per hour)
- High delete performance, for aging-out(deletion) of old data
- Automatic age-off oldest data when storage limit is reached
- S3 support (Version 2) with one bucket "data"
- Build in prometheus support.
- Build in ACME support.
- Support object/blob compression.
- Support UUID version 4 with human readable timestamp(`YYYYMMDD-HHMM`) in the first two sections.
- Support UUID version 1 according to RFC 4122
- Built-in web-GUI with support for uploading/downloading and browsing files on disk
- Support HTTP Raw-Upload and HTTP-Multipart with multiple files

Cons
- Not possible to delete or overwrite single blob, it must age-off. (Data is frozen within the glacier)
- Only accept Time-UUID as identifiers.

Ongoing work
- Blob encryption
- Blob metadata
- Swift storage
- Multiple variants of same file

## Example RawUpload
```
POST /rawupload/[[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}]
```

## Example Download/Get
```
GET /get/[[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}]
```

## Example Multipart Upload with multiple files
```
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=---------------------------273754160213256655563977755994

-----------------------------273754160213256655563977755994
Content-Disposition: form-data; name="file"; filename="20221102-1326-4897-aeed-aaaaaaaaaaaa"
Content-Type: application/octet-stream

test

-----------------------------273754160213256655563977755994
Content-Disposition: form-data; name="file"; filename="20221102-1326-4897-aeed-bbbbbbbbbbbb"
Content-Type: application/octet-stream

test

-----------------------------273754160213256655563977755994
Content-Disposition: form-data; name="file"; filename="20221102-1326-4897-aeed-cccccccccccc"
Content-Type: application/octet-stream

test

-----------------------------273754160213256655563977755994--
```


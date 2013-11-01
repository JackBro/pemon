//#include <ntddk.h>
#include <ntifs.h>
#include "ntpath.h"

#define TAG_SANDBOX		'SBOX'

#define MAX_FILE_PATH		270


#define TYPE_UNKNOWN	-3
#define TYPE_NAME_INVALID -2
#define TYPE_NOT_EXIST	-1
#define TYPE_FILE	0
#define TYPE_DIRECTORY	1
#define TYPE_DRIVER	2

#define HARDDISK_VOLUME		L"\\Device\\HarddiskVolume"
#define HADRDISK_VOLUME_CCH	wcslen( L"\\Device\\HarddiskVolume" )

#define GLOBAL			L"\\??"
#define GLOBAL_CCH		wcslen( L"\\??" )

#define LENGTH_8_DOT_3		12



WCHAR* wcsnchr( const wchar_t * string, wchar_t chr, int len )
{
	USHORT i = 0;
	USHORT ch = len >> 1;
	while( i < ch ) {
		if ( *( string + i ) == chr )
			return (WCHAR*)( string + i );	
		i ++;
	}

	return NULL;
}

BOOLEAN IsBackslashAtEnd( UNICODE_STRING* us )
{
	////ZASSERT( us, return FALSE );
	////ZASSERT( us->Buffer, return FALSE );
	if( us->Length == 0 ) {
		return FALSE;
	}

	if( us->Buffer[ ( us->Length >> 1 )- 1 ] == L'\\' ){
		return TRUE;
	}	
	return FALSE;
}

BOOLEAN IsBackslashAtBegin( UNICODE_STRING* us )
{
	////ZASSERT( us, return FALSE );
	////ZASSERT( us->Buffer, return FALSE );
	if( us->Length == 0 ) {
		return FALSE;
	}

	if( us->Buffer[0] == L'\\' ){
		return TRUE;
	}	
	return FALSE;
}

BOOLEAN 
RtlCompareUnicodeStringSafe(UNICODE_STRING* us, WCHAR* str)
{
	if (str == NULL) {
		return FALSE;
	}

	int len = wcslen(str);

	if (len <= 0 ) {
		return FALSE;
	}

	if (us->Length < len * 2) {
		return FALSE;
	}

	if (wcsncmp(us->Buffer, str, len) == 0) {
		return TRUE;
	} else {
		return TRUE;
	}
}

VOID RtlRemoveUnicodeBackslash( UNICODE_STRING* us )
{
	if( us->Buffer[ ( us->Length >> 1 )- 1 ] == L'\\' ){
		us->Buffer[ ( us->Length >> 1 )- 1 ] = 0;
		us->Length -= sizeof( WCHAR );
	}	
}

VOID RtlRemoveUnicodeStringPrefix(UNICODE_STRING* us, WCHAR* Prefix)
{
	INT PrefixLen = wcslen(Prefix);

	if (0 == wcsncmp(us->Buffer, Prefix, PrefixLen)) {
		us->Length -= PrefixLen;
		RtlCopyMemory(us->Buffer, us->Buffer + PrefixLen, us->Length);
	}
}

WCHAR* RtlFindLastChar( UNICODE_STRING* us, WCHAR chr )
{
	
	INT ch = (INT)( us->Length >> 1 );
	INT i  =  ch - 1;
	while( i >= 0 ) {
		if ( us->Buffer[i] == chr )
			return &us->Buffer[i];	
		i--;
	}

	return NULL;
}

VOID RtlClearUnicodeString( UNICODE_STRING* us )
{
	//ZASSERT( us, return );
	us->Length = 0;
	RtlZeroMemory( us->Buffer, us->MaximumLength );
}

NTSTATUS RtlAppendUnicodeToStringSafe( UNICODE_STRING* us, WCHAR* wz, 
				       USHORT cch_wz )
{
	if( ( us->MaximumLength - us->Length ) < (USHORT)(cch_wz * sizeof( WCHAR )) ) {
		//缓冲区不够了， 
		return STATUS_BUFFER_TOO_SMALL;
	} else {
		wcsncpy( us->Buffer + ( us->Length >> 1 ), wz, cch_wz );
		us->Length += cch_wz * sizeof( WCHAR ) ;
		return STATUS_SUCCESS;
	}
}

VOID    RtlReleaseUnicodeString( UNICODE_STRING* us )
{
	if( us &&  us->Buffer ) {
		ExFreePoolWithTag( us->Buffer, TAG_SANDBOX );
	}
}

NTSTATUS RtlAllocateUnicodeString( UNICODE_STRING* us, USHORT cch_max )
{
	WCHAR* buffer = NULL;

	if( !us ) {
		return STATUS_INVALID_PARAMETER;
	}

	buffer = (WCHAR*)ExAllocatePoolWithTag( NonPagedPool, 
			cch_max * sizeof( WCHAR )+ 4, TAG_SANDBOX );
	if( buffer == NULL ){
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory( buffer, cch_max * sizeof( WCHAR ) );

	us->Length = 0;
	us->MaximumLength = (USHORT)( cch_max * sizeof( WCHAR ) );
	us->Buffer = buffer;
	*(ULONG*)( (CHAR*)buffer + cch_max * sizeof( WCHAR ) ) = 'TEST';
	return STATUS_SUCCESS;
}

extern "C"
WCHAR* RtlSearchString( UNICODE_STRING* us, WCHAR* str, BOOLEAN bCaseSensitive )
{
	WCHAR* tmpstr = NULL;
	WCHAR* pos = NULL;

	if( us == NULL || str == NULL )
		return NULL;

	if( us->Length == 0 ) 
		return NULL;

	tmpstr = (WCHAR*)ExAllocatePoolWithTag( NonPagedPool, 
				us->Length + sizeof( WCHAR ), TAG_SANDBOX );
	RtlZeroMemory( tmpstr, us->Length + sizeof( WCHAR ) );
	RtlCopyMemory( tmpstr, us->Buffer, us->Length );
		
	if( bCaseSensitive ) {
		//大小写敏感
		pos = wcsstr( tmpstr, str );
	} else {
		//大小写不敏感
		WCHAR* tagstr = NULL;
		INT taglen = ( wcslen( str ) + 1 )* sizeof( WCHAR ) ;
		tagstr = (WCHAR*)ExAllocatePoolWithTag( NonPagedPool, taglen, TAG_SANDBOX );
		if( tagstr == NULL ) {
			goto ret_door;
		}
		RtlZeroMemory( tagstr, taglen );
		RtlCopyMemory( tagstr, str, taglen - sizeof( WCHAR ) );
		
		_wcslwr( tagstr );
		_wcslwr( tmpstr );
		pos = wcsstr( tmpstr, tagstr );
		ExFreePoolWithTag( tagstr, TAG_SANDBOX );
		tagstr = NULL;
	}
	
	if( pos )
		pos = us->Buffer + ( pos - tmpstr );
ret_door:
	ExFreePoolWithTag( tmpstr, TAG_SANDBOX );
	return pos;
}


NTSTATUS	GetLongPath( UNICODE_STRING* usDir, UNICODE_STRING* usShortFileName, 
			     UNICODE_STRING* usLongFileName )
{
	FILE_BOTH_DIR_INFORMATION* info = NULL;
	HANDLE			hFind = NULL;
	OBJECT_ATTRIBUTES	oa = {0};
	IO_STATUS_BLOCK		iosb = {0};
	ULONG			infolen = 1024;
	NTSTATUS		status = STATUS_SUCCESS;
	WCHAR*			pos = NULL;
	ULONG			restlen = 0;

	//短文件路径名称
	//查询该文件的长文件名
	pos = RtlSearchString( usDir, HARDDISK_VOLUME, FALSE );
	if( pos != NULL ) {
		restlen = usDir->Length - 
			sizeof( WCHAR ) * wcslen( HARDDISK_VOLUME );
		pos += wcslen( HARDDISK_VOLUME );

		pos = wcsnchr( pos, L'\\', restlen );
		if( pos == NULL ) {
			//说明就是\\Device\\HarddiskVolumeX
			//加上一个BackSlash
			RtlAppendUnicodeToString( usDir, L"\\" );
		}
	}

	InitializeObjectAttributes( &oa, usDir, OBJ_CASE_INSENSITIVE, NULL, NULL );
	status = ZwOpenFile( &hFind, FILE_LIST_DIRECTORY | SYNCHRONIZE, 
		             &oa, &iosb, FILE_SHARE_READ, 
			     FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	info = (FILE_BOTH_DIR_INFORMATION*)ExAllocatePoolWithTag( NonPagedPool, 
							infolen, TAG_SANDBOX );
	if( info == NULL ) {
		status = STATUS_MEMORY_NOT_ALLOCATED;
		goto ret_door;
	}
	RtlZeroMemory( info , infolen );

	status = ZwQueryDirectoryFile( hFind, NULL, NULL, NULL, &iosb, info, 
				       infolen, FileBothDirectoryInformation, 
				       TRUE, usShortFileName, TRUE );
	if( !NT_SUCCESS( status ) ) {
		//文件可能是不存在的
		goto ret_door;
	}

	RtlAppendUnicodeToStringSafe( usLongFileName, info->FileName, 
				       info->FileNameLength >> 1 );

ret_door:
	if( hFind ) {
		ZwClose( hFind );
		hFind = NULL;
	}

	if( info ) {
		ExFreePool( info );
		info = NULL;
	}

	return status;
}

NTSTATUS  
ParseGlobalSymbolicLick(UNICODE_STRING* usFullPath, UNICODE_STRING* usVolumePath)
{
	NTSTATUS	status = STATUS_SUCCESS;
	HANDLE hSymbol = NULL;
	OBJECT_ATTRIBUTES   attribute = {0};
	UNICODE_STRING usSymbol = {0};
	UNICODE_STRING usTarget = {0};
	ULONG	ReturnLength = 0;
	USHORT cchFileName = 0;
	USHORT cchSymbol = wcslen( L"\\??\\" ) + 2 ;

	usVolumePath->Length = usFullPath->Length;
	RtlCopyMemory(usVolumePath->Buffer, usFullPath->Buffer, usFullPath->Length);

	RtlCopyMemory( &usSymbol, usFullPath, sizeof( UNICODE_STRING ) );
	usSymbol.Length = cchSymbol *sizeof( WCHAR );
	InitializeObjectAttributes( &attribute, &usSymbol, 
				OBJ_CASE_INSENSITIVE, NULL, NULL );
	status = ZwOpenSymbolicLinkObject( &hSymbol, GENERIC_READ, &attribute );
	if( !NT_SUCCESS( status ) ) {
		//在Explorer.exe启动时， 会枚举所有盘符
		//\\??\\A:, \\??\\B:, \\??\\C:, ......
		goto ret_door;
	}

	status = RtlAllocateUnicodeString( &usTarget, MAX_FILE_PATH );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	status = ZwQuerySymbolicLinkObject( hSymbol, &usTarget, &ReturnLength );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	//ZSUCCESS( RtlRemoveUnicodeString( &usTarget, L"\\Device\\" ) );
	cchFileName = ( usFullPath->Length - 
			sizeof( WCHAR ) * cchSymbol  ) >> 1;
	status = RtlAppendUnicodeToStringSafe( &usTarget, 
		usFullPath->Buffer + cchSymbol, cchFileName );
	if( NT_SUCCESS( status ) ){
		RtlCopyUnicodeString( usVolumePath, &usTarget );
	}

ret_door:
	if( hSymbol ) {
		ZwClose( hSymbol );
		hSymbol = NULL;
	}

	RtlReleaseUnicodeString( &usTarget );
	return status;
}

NTSTATUS 
ParseSystemRootSymbolicLick(UNICODE_STRING* usFullPath, UNICODE_STRING* usVolumePath, 
	WCHAR* Prefix)
{
	NTSTATUS	status = STATUS_SUCCESS;
	WCHAR* pos = NULL;
	HANDLE hSymbol = NULL;
	UNICODE_STRING usTarget = {0};
	UNICODE_STRING usTarget2 = {0}; 
	ULONG	ReturnLength = 0;
	OBJECT_ATTRIBUTES   attribute = {0};
	UNICODE_STRING usSymbol = {0};
	USHORT cchFileName = 0;
	USHORT cchSymbol = (USHORT)wcslen(Prefix);

	usVolumePath->Length = usFullPath->Length;
	RtlCopyMemory(usVolumePath->Buffer, usFullPath->Buffer, usFullPath->Length);

	RtlCopyMemory( &usSymbol, usFullPath, sizeof( UNICODE_STRING ) );
	usSymbol.Length = cchSymbol *sizeof( WCHAR );

	//解析第一个符号
	//SystemRoot是\\Device\\Harddisk0\\Partition1的符号链接
	InitializeObjectAttributes( &attribute, &usSymbol, 
					OBJ_CASE_INSENSITIVE, NULL, NULL );
	status = ZwOpenSymbolicLinkObject( &hSymbol, GENERIC_READ, &attribute );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	status = RtlAllocateUnicodeString( &usTarget, MAX_FILE_PATH );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	status = ZwQuerySymbolicLinkObject( hSymbol, &usTarget, &ReturnLength );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	//解析出第二个符号
	//\\Device\\Harddisk0\\Partition1是\\Device\\HarddiskVolume1的链接
	RtlCopyMemory( &usSymbol, &usTarget, sizeof( UNICODE_STRING ) );
	pos = RtlSearchString( &usSymbol, L"\\Partition", TRUE );
	if( pos == NULL ) {
		status = STATUS_NOT_FOUND;
		goto ret_door;
	}

	pos += wcslen( L"\\Partition" );
	pos = wcschr( pos, L'\\' );
	if( pos == NULL ) {
		status = STATUS_NOT_FOUND;
		goto ret_door;
	}

	usSymbol.Length = ( pos - usSymbol.Buffer ) * sizeof( WCHAR );
	InitializeObjectAttributes( &attribute, &usSymbol, 
					OBJ_CASE_INSENSITIVE, NULL, NULL );
	status = ZwOpenSymbolicLinkObject( &hSymbol, GENERIC_READ, &attribute );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	status =  RtlAllocateUnicodeString( &usTarget2,MAX_FILE_PATH );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	status = ZwQuerySymbolicLinkObject( hSymbol, &usTarget2, &ReturnLength );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	cchFileName = ( usTarget.Length - 
		sizeof( WCHAR ) *( pos - usTarget.Buffer ) ) >> 1;
	status =  RtlAppendUnicodeToStringSafe( &usTarget2, pos, cchFileName );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	cchFileName = ( usFullPath->Length - sizeof( WCHAR ) * cchSymbol  ) >> 1;
	status =  RtlAppendUnicodeToStringSafe( &usTarget2, 
		usFullPath->Buffer + cchSymbol, cchFileName );
	if( NT_SUCCESS( status ) ) {
		RtlCopyUnicodeString( usVolumePath, &usTarget2 );
	}

ret_door:
	if( hSymbol ) {
		ZwClose( hSymbol );
		hSymbol = NULL;
	}

	RtlReleaseUnicodeString( &usTarget );
	RtlReleaseUnicodeString( &usTarget2 );
	return status;
}


NTSTATUS 
ParseNextFileNode( UNICODE_STRING* usPath, INT bFinalDirectory, INT* bDirNode )
{
	WCHAR* pos = NULL;
	WCHAR* begin = NULL; 
	USHORT namelen = 0;
	USHORT restlen = 0;

	if( usPath->Length == 0 ) {

		if( 0 == wcsncmp( usPath->Buffer, HARDDISK_VOLUME, HADRDISK_VOLUME_CCH ) ) {
			//寻找下一个
			INT cch = HADRDISK_VOLUME_CCH;
			restlen = usPath->MaximumLength 
				- cch * sizeof( WCHAR );
			begin = usPath->Buffer + cch;
			pos = wcsnchr( begin, L'\\', restlen );
			if( pos ) {
				usPath->Length = ( pos - usPath->Buffer ) * sizeof( WCHAR );
				*bDirNode = TYPE_DRIVER;
				return STATUS_SUCCESS;
			} else {
				//说明就是\\Device\\HarddiskVolumeX
				usPath->Length = usPath->MaximumLength;
				*bDirNode = TYPE_DRIVER;
				return STATUS_SUCCESS;
			}

		} else if( 0 == wcsncmp( usPath->Buffer, GLOBAL, GLOBAL_CCH ) ){
			INT cch = GLOBAL_CCH;
			restlen = usPath->MaximumLength - cch * sizeof( WCHAR );
			begin = usPath->Buffer + cch;
			pos = wcsnchr( begin, L'\\', restlen );
			if( pos ) {
				usPath->Length = ( pos - usPath->Buffer ) * sizeof( WCHAR );
				*bDirNode = TYPE_DRIVER;
			} else {
				*bDirNode = TYPE_UNKNOWN;
				return STATUS_NOT_FOUND;
			} 
		} else {
			////ZASSERT( FALSE, return STATUS_NOT_SUPPORTED );
		}
	}

	if( usPath->Length < usPath->MaximumLength ) {

		//解析下一个节点
		//逐层判断文件路径是否存在
		begin = usPath->Buffer + ( usPath->Length >> 1 ) + 1;
		restlen =  usPath->MaximumLength - usPath->Length - sizeof( WCHAR ) ;

		pos = wcsnchr( begin, L'\\', restlen );
		if( pos == NULL ) {
			//最后一层
			usPath->Length = usPath->MaximumLength;
			*bDirNode = bFinalDirectory;
		} else {	
			//后面还有
			usPath->Length = ( pos - usPath->Buffer ) * sizeof( WCHAR );
			*bDirNode = TYPE_DIRECTORY;
		}

		//ZASSERT( usPath->Length <= usPath->MaximumLength, return STATUS_BUFFER_OVERFLOW );

	} else if( usPath->Length == usPath->MaximumLength ) {
		//已经没有节点了
		return STATUS_NO_MORE_ENTRIES;
	} else {
		//ZASSERT( FALSE, return STATUS_NOT_SUPPORTED );
	}

	return STATUS_SUCCESS;
}


BOOLEAN IsShortPath( UNICODE_STRING* usPath )
{
	//判断最后的节点
	INT cch = 0;
	INT rest_cch = 0;
	WCHAR* pos = RtlFindLastChar( usPath, L'\\' );
	if( pos == NULL ) {
		//没有找到
		return FALSE;
	}

	//判断节点长度
	cch = (INT)( usPath->Length >> 1 );
	rest_cch = cch - ( pos - usPath->Buffer );
	if( rest_cch > LENGTH_8_DOT_3 ) {
		return FALSE;
	}

	if( NULL == wcsnchr( pos, L'~',  rest_cch * sizeof( WCHAR ) ) ) {
		return FALSE;
	}

	return TRUE;
}


NTSTATUS	
ShortPathToLongPath( UNICODE_STRING* usShortPath, INT bDirectory )
{
	NTSTATUS	status = STATUS_SUCCESS;
	UNICODE_STRING	usNode = {0};
	INT		bDirThisNode = 0;
	UNICODE_STRING	usLongPath = {0};
	UNICODE_STRING	usLongFileName = {0};

	status = RtlAllocateUnicodeString( &usLongPath, MAX_FILE_PATH );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	status = RtlAllocateUnicodeString( &usLongFileName, MAX_FILE_PATH );
	if( !NT_SUCCESS( status ) ) {
		goto ret_door;
	}

	RtlCopyMemory( &usNode, usShortPath, sizeof( UNICODE_STRING ) );
	usNode.Length = 0;
	usNode.MaximumLength = usShortPath->Length;

	//解析每一个节点
	while( NT_SUCCESS( status = ParseNextFileNode( &usNode, bDirectory, &bDirThisNode ) ) ) {


		UNICODE_STRING	usFileName = {0};
		WCHAR* pos = NULL;

		//判断是否短路径名称
		if( !IsShortPath( &usNode ) ) {
			//长路径名称
			if( bDirThisNode == TYPE_DRIVER ) {
				RtlCopyUnicodeString( &usLongPath, &usNode );
			} else {
				pos = RtlFindLastChar( &usNode, L'\\' );
				//ZASSERT( pos, INT3 );
				usFileName.Buffer = pos + 1;
				usFileName.Length = usNode.Length - ( pos - usNode.Buffer + 1 ) * sizeof( WCHAR );
				usFileName.MaximumLength = usFileName.Length;	
				if( !IsBackslashAtEnd( &usLongPath ) ) 
					RtlAppendUnicodeToString( &usLongPath, L"\\" );
				RtlAppendUnicodeStringToString( &usLongPath, &usFileName );
			}
		} else {
			RtlClearUnicodeString( &usLongFileName );
			pos = RtlFindLastChar( &usNode, L'\\' );
			//ZASSERT( pos, INT3 );
			usFileName.Buffer = pos + 1;
			usFileName.Length = usNode.Length 
					- ( pos - usNode.Buffer + 1 ) * sizeof( WCHAR );
			usFileName.MaximumLength = usFileName.Length;
			status = GetLongPath( &usLongPath, &usFileName, &usLongFileName );
			if( !NT_SUCCESS( status ) ) {
				goto ret_door;
			}
			if( !IsBackslashAtEnd( &usLongPath ) ) 
				RtlAppendUnicodeToString( &usLongPath, L"\\" );
			RtlAppendUnicodeStringToString( &usLongPath, &usLongFileName );
		}
	}
	
	//ZASSERT( status == STATUS_SUCCESS || status == STATUS_NO_MORE_ENTRIES
	//	 || status == STATUS_NO_SUCH_FILE || status == STATUS_NOT_FOUND, 
	//	 goto ret_door );
	
	status = STATUS_SUCCESS;

ret_door:
	RtlCopyUnicodeString( usShortPath, &usLongPath );
	RtlReleaseUnicodeString( &usLongPath );
	RtlReleaseUnicodeString( &usLongFileName );
	return status;
}




NTSTATUS
ParseDosName(UNICODE_STRING* usVolumePath, UNICODE_STRING* usDosPath)
{
	NTSTATUS Status;    
    
    if(NULL == usVolumePath)
    {        
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING usTargetVolumeName;

    usTargetVolumeName.Buffer = usVolumePath->Buffer;
	usTargetVolumeName.MaximumLength = 
		usTargetVolumeName.Length = wcslen(L"\\Device\\HarddiskVolumeX") * 2;
    
    UNICODE_STRING usDosName;
    WCHAR Buffer[32] = {L"\\??\\X:"};
    RtlInitUnicodeString(&usDosName, Buffer);
    
    WCHAR c;
    for( c = L'A' ; c < ('Z'+1); ++c )
    {
        usDosName.Buffer[wcslen(L"\\??\\")] = c;

	    WCHAR *dbuf = NULL;
	    
	   
	    ULONG length;
	    
	    OBJECT_ATTRIBUTES attrib;
	    InitializeObjectAttributes(
	        &attrib,
	        &usDosName,
	        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
	        NULL,NULL);
	    
	    HANDLE DosHandle;
	    Status = ZwOpenSymbolicLinkObject(
	    	&DosHandle,
	        GENERIC_READ,
	        &attrib);
	    
	    if( !NT_SUCCESS(Status))
	    {        
	        continue;
	    }
	    
	    WCHAR VolumeNameBuffer[MAX_FILE_PATH] = {0};
	    UNICODE_STRING usVolumeName;
	    RtlInitEmptyUnicodeString(&usVolumeName, VolumeNameBuffer, sizeof(VolumeNameBuffer));
	    
	    Status = ZwQuerySymbolicLinkObject(
	        DosHandle,
	        &usVolumeName,
	        &length);
	    
	    ZwClose(DosHandle);
        
        if (NT_SUCCESS(Status) &&
        	RtlCompareUnicodeString(&usTargetVolumeName, &usVolumeName,TRUE) == 0)
        {               
        	RtlCopyUnicodeString(usDosPath, &usDosName);

        	RtlAppendUnicodeToStringSafe(usDosPath,
        		usVolumePath->Buffer + wcslen(L"\\Device\\HarddiskVolumeX"), 
        		usVolumePath->Length - wcslen(L"\\Device\\HarddiskVolumeX") * 2);

           	return STATUS_SUCCESS;
        }
        
    }

    return STATUS_NOT_FOUND;
}



//将\\??\\C:\XXXX转换成\\Device\\HarddiskVolume
NTSTATUS 
DosNameToVolumeName(UNICODE_STRING* usDosName, UNICODE_STRING* usVolumeName)
{
	NTSTATUS 	status;

	if( usDosName == NULL || usDosName->Buffer == NULL ) {
		return STATUS_INVALID_PARAMETER;
	}

	//判断是否\\??
	if( usDosName->Buffer == RtlSearchString(usDosName, L"\\??\\", FALSE ) ) {

		//转换为
		status = ParseGlobalSymbolicLick( usDosName, usVolumeName );

	} else if( usDosName->Buffer == 
		RtlSearchString( usDosName, L"\\Device\\", FALSE ) ) {

		//已经是标准文件路径格式了
		//} else if( 0 == wcsncmp( usFullPath->Buffer, L"\\Device",
		//	wcslen( L"\\Device" ) ) ) {
		//		//已经是标准文件路径格式了
		RtlCopyUnicodeString(usVolumeName, usDosName);
		status = STATUS_SUCCESS;

	} else if( usDosName->Buffer == 
		RtlSearchString( usDosName, L"\\WINDOWS", FALSE ) ) {

		WCHAR PathBuffer[MAX_FILE_PATH] = {0};
		UNICODE_STRING usPath;
		RtlInitEmptyUnicodeString(&usPath, PathBuffer, sizeof(PathBuffer));

		RtlAppendUnicodeToStringSafe(&usPath, L"\\??\\C:", wcslen(L"\\??\\C:"));
		RtlAppendUnicodeStringToString(&usPath, usDosName);

		status = ParseGlobalSymbolicLick(&usPath, usVolumeName);

	} else {


		WCHAR* pos = wcsnchr(usDosName->Buffer + 1, '\\', usDosName->Length - sizeof(WCHAR));
		if (pos != NULL) {

			WCHAR Prefix[128] = {0};
			wcsncpy(Prefix, usDosName->Buffer, pos - usDosName->Buffer);
			status = ParseSystemRootSymbolicLick(usDosName, usVolumeName, Prefix);

		} else {

			//当Explorer枚举盘符的时候， 有些盘符是不存在的
			//还有上层会传一些非法的路径进来
			status = STATUS_NOT_SUPPORTED;
		}
		
	}

	if (NT_SUCCESS(status)) {

		if( IsBackslashAtEnd( usVolumeName ) ) {
			RtlRemoveUnicodeBackslash( usVolumeName );
		}
		status = ShortPathToLongPath( usVolumeName, FALSE );
	}

	

	return status;
}


NTSTATUS  
VolumeNameToDosName(UNICODE_STRING* usVolumeName, UNICODE_STRING* usDosName)
{
	NTSTATUS 	status;

	if( usVolumeName == NULL || usVolumeName->Buffer == NULL ) {
		return STATUS_INVALID_PARAMETER;
	}

	//判断是否\\??
	if( usVolumeName->Buffer == RtlSearchString(usVolumeName, L"\\??\\", FALSE ) ) {

		// 已经是DOS NAME格式了
		RtlCopyUnicodeString(usDosName, usVolumeName);
		status = STATUS_SUCCESS;

	} else if( usVolumeName->Buffer == 
		RtlSearchString( usVolumeName, L"\\Device\\HarddiskVolume", FALSE ) ) {

		//已经是标准文件路径格式了
		//} else if( 0 == wcsncmp( usFullPath->Buffer, L"\\Device",
		//	wcslen( L"\\Device" ) ) ) {
		//		//已经是标准文件路径格式了

		status = ParseDosName(usVolumeName, usDosName);


	} else if( usVolumeName->Buffer == 
		RtlSearchString( usVolumeName, L"\\SystemRoot", FALSE ) ) {

		UNICODE_STRING usVolumePath = {0};
		WCHAR Buffer[MAX_FILE_PATH] = {0};
		RtlInitEmptyUnicodeString(&usVolumePath, Buffer, MAX_FILE_PATH);

		status = ParseSystemRootSymbolicLick(usVolumeName, &usVolumePath, L"\\SystemRoot");
		if (NT_SUCCESS(status)) {
			ParseDosName(&usVolumePath, usDosName);	
		}
		
	} else if (usVolumeName->Buffer == 
		RtlSearchString(usVolumeName, L"\\WINDOWS\\", TRUE)) {

		RtlAppendUnicodeToString(usDosName, L"\\??\\C:");
		status = RtlAppendUnicodeStringToString(usDosName, usVolumeName);

	} else if( usVolumeName->Buffer == 
		RtlSearchString( usVolumeName, L"\\Device\\NamedPipe", TRUE ) ) {

		//管道， 放过
		return STATUS_NOT_SUPPORTED;

	} else if( usVolumeName->Buffer == 
		RtlSearchString( usVolumeName, L"\\Device\\KsecDD", TRUE ) ) {

		return STATUS_NOT_SUPPORTED;

	} else if( usVolumeName->Buffer == 
		RtlSearchString( usVolumeName, L"\\Device\\Tcp", TRUE ) ) {

		return STATUS_NOT_SUPPORTED;

	} else {

		//当Explorer枚举盘符的时候， 有些盘符是不存在的
		//还有上层会传一些非法的路径进来
		return STATUS_NOT_SUPPORTED;
	}

	if (NT_SUCCESS(status)) {
		RtlRemoveUnicodeStringPrefix(usDosName, L"\\??\\");
	}

	return status;
}

#include "pe.h"

#include <Winternl.h>
#include <iostream>
#include <map>

std::string data_drictory_str[16] = {
	"Export Table",
	"Import Table",
	"Resource Table",
	"Exception Table",
	"Security Table",
	"Base Relocation Table",
	"Debug",
	"Copyright",
	"Global Ptr",
	"Thread local storage",
	"Load configuration",
	"Bound import",
	"Import Address table",
	"Delay Import",
	"Com descriptor",
	"NULL"
};

bool PE_INFO(LPCVOID base, DWORDX length)
{
	PIMAGE_DOS_HEADER p_image_dos_header = (PIMAGE_DOS_HEADER)base;
	if (p_image_dos_header->e_magic != IMAGE_DOS_SIGNATURE)  //Dos 可执行文件标记 MZ  0x5A4D
	{
		std::cout << "NOT MZ" << std::endl;
		return false;
	}

	//p_image_dos_header->e_lfanew; PE 文件头偏移
	//这里 PIMAGE_NT_HEADERS 在不同平台下对应 32 位 PIMAGE_NT_HEADERS32，64 位 PIMAGE_NT_HEADERS64
	PIMAGE_NT_HEADERS p_image_nt_header = (PIMAGE_NT_HEADERS)((DWORDX)base + p_image_dos_header->e_lfanew);
	if(p_image_nt_header->Signature != IMAGE_NT_SIGNATURE) // PE 可执行文件标记 PE00  0x00004550
	{ 
		std::cout << "NOT PE" << std::endl;
		return false;
	}
	
	IMAGE_FILE_HEADER image_file_header = p_image_nt_header->FileHeader;
	// Machine 见 IMAGE_FILE_MACHINE_*  
	image_file_header.Machine;			//可执行文件的目标 CPU 类型
	image_file_header.NumberOfSections;	//区块 Section 的数目
	image_file_header.TimeDateStamp;	//文件的创建时间
	image_file_header.PointerToSymbolTable; // COFF 符号表的文件偏移位置
	image_file_header.NumberOfSymbols;		// 如果有 COFF 符号表，代表其中的符号数目
	image_file_header.SizeOfOptionalHeader; // 数据的大小，32 位与 64 区别在这里。32 通常是 00E0h，64 常为 00F0h
	image_file_header.Characteristics;		// 文件属性, IMAGE_FILE_xxx EXE 一般是 010fh， DLL 一般是 2102h

	//32 位 IMAGE_OPTIONAL_HEADER32，64 位 IMAGE_OPTIONAL_HEADER64
	IMAGE_OPTIONAL_HEADER image_optional_header = p_image_nt_header->OptionalHeader;
	image_optional_header.BaseOfCode; //代码段起始 RVA
	image_optional_header.ImageBase;  //文件在内存中的首选载入地址
	image_optional_header.SectionAlignment;	//载入内存时候的区块对齐大小     0x1000
	image_optional_header.FileAlignment;	//磁盘上的 PE 文件的区块对齐大小 0x200
	image_optional_header.SizeOfImage;		//映像载入内存后的总尺寸
	image_optional_header.SizeOfHeaders;	//DOS 头、PE文件头、区块表的总尺寸
	image_optional_header.CheckSum;			//校验和
	image_optional_header.AddressOfEntryPoint; //也就是上文提到的OEP，程序源入口点。
	
	image_optional_header.NumberOfRvaAndSizes; //数据目录的项数，从 Windows NT 以来一直是16... 我读出来的是 0
	PIMAGE_DATA_DIRECTORY p_image_data_directory = image_optional_header.DataDirectory;
	for (int i = 0;i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
	{
		p_image_data_directory[i].VirtualAddress;	//数据块的起始 RVA
		p_image_data_directory[i].Size;				//数据块的长度
		std::cout << "DataDirectory "<< 
			data_drictory_str[i].c_str()<<" VirtualAddress:" << std::hex << p_image_data_directory[i].VirtualAddress
			<< " Size:" << std::hex << p_image_data_directory[i].Size << std::endl;
	}
	
	std::map<DWORDX, DWORDX> section_rva_2_offset_map;  // section 虚拟地址 VirtualAddress -> 偏移 (tmp.VirtualAddress - tmp.PointerToRawData)

	//区块
	PIMAGE_SECTION_HEADER p_image_section_header_base = (PIMAGE_SECTION_HEADER)((DWORDX)p_image_nt_header + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < image_file_header.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER tmp = p_image_section_header_base[i];
		tmp.Name;				//8 字节块名
		tmp.Misc.VirtualSize;	//实际使用的区块大小，对齐处理前
		tmp.VirtualAddress;		//装载在内存中的 RVA
		tmp.SizeOfRawData;		//在磁盘中所占的空间
		tmp.PointerToRawData;	//在磁盘文件中的偏移
		tmp.Characteristics;	//块属性 可读可写可执行等

		section_rva_2_offset_map[tmp.VirtualAddress] = tmp.VirtualAddress - tmp.PointerToRawData;


		std::cout << "Section Name:" << (const char*)tmp.Name << 
			" VirtualSize:"<< std::hex <<tmp.Misc.VirtualSize <<
			" VirtualAddress:" << std::hex << tmp.VirtualAddress <<
			" SizeOfRawData:" << std::hex << tmp.SizeOfRawData <<
			" PointerToRawData:" << std::hex << tmp.PointerToRawData <<
			" Characteristics:" << std::hex << tmp.Characteristics << std::endl;
		
	}

	//输入表  p_image_nt_header->OptionalHeader.DataDirectory[1] 存放 第二个
	//PIMAGE_IMPORT_DESCRIPTOR p_image_import_descriptor_base
	//DWORDX import_descriptor_offset = 0;
	{
		PIMAGE_IMPORT_DESCRIPTOR p_image_import_descriptor_base = NULL;  //输入表基地址
		DWORDX import_descriptor_offset = 0;

		auto it = section_rva_2_offset_map.upper_bound(p_image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); --it;
		if (p_image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL && it != section_rva_2_offset_map.end())
		{
			import_descriptor_offset = it->second;
			p_image_import_descriptor_base = (PIMAGE_IMPORT_DESCRIPTOR)((DWORDX)base + p_image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - import_descriptor_offset);

			for (int i = 0;;++i)
			{
				IMAGE_IMPORT_DESCRIPTOR tmp = p_image_import_descriptor_base[i];
				tmp.OriginalFirstThunk; //指向输入名称表(INT)的RVA IMAGE_THUNK_DATA  不可改写
				tmp.TimeDateStamp;		//时间标志
				tmp.ForwarderChain;		//第一个被转向的 API 索引,一般为 0，在程序引用一个 DLL 中的 API，这个 API 又引用其他 DLL 的 API 使用
				tmp.Name;				//DLL 名字指针
				tmp.FirstThunk;			//指向输入地址表(IAT)的 RVA, IMAGE_THUNK_DATA 的数组，PE 装载器重写
				if (tmp.Name == NULL) break;

				std::cout << "IMPORT_DESCRIPTOR Name:" << (const char*)((DWORDX)base + tmp.Name - import_descriptor_offset) << std::endl;

				PIMAGE_THUNK_DATA p_oft_base = (PIMAGE_THUNK_DATA)((DWORDX)base + tmp.OriginalFirstThunk - import_descriptor_offset);
				for (int j = 0;; ++j)
				{
					IMAGE_THUNK_DATA ith_tmp = p_oft_base[j];
					if(ith_tmp.u1.ForwarderString == NULL) break;
					if (IMAGE_SNAP_BY_ORDINAL(ith_tmp.u1.Ordinal))
					{
						//是序列号
						//std::cout << "\tIMAGE_THUNK_DATA Hint:" << std::hex << IMAGE_ORDINAL(ith_tmp.u1.Ordinal) << std::endl;
					}
					else
					{
						//是 RVA
						PIMAGE_IMPORT_BY_NAME p_image_import_by_name = (PIMAGE_IMPORT_BY_NAME)((DWORDX)base + ith_tmp.u1.Ordinal - import_descriptor_offset);
						p_image_import_by_name->Hint; //本函数在其所驻留 DLL 的输出表中的序号
						p_image_import_by_name->Name; //输入函数的函数名

						//std::cout << "\tIMAGE_THUNK_DATA IMAGE_IMPORT_BY_NAME Hint:" << std::hex << p_image_import_by_name->Hint <<" Name:"<< (const char*)p_image_import_by_name->Name << std::endl;
					}
					//std::cout << "\tOriginalFirstThunk IMAGE_THUNK_DATA :" << std::hex << ith_tmp.u1.Ordinal << std::endl;;
				}

				PIMAGE_THUNK_DATA p_ft_base = (PIMAGE_THUNK_DATA)((DWORDX)base + tmp.FirstThunk - import_descriptor_offset);
				for (int j = 0;; ++j)
				{
					IMAGE_THUNK_DATA ith_tmp = p_ft_base[j];
					if (ith_tmp.u1.ForwarderString == NULL) break;
					if (IMAGE_SNAP_BY_ORDINAL(ith_tmp.u1.Ordinal))
					{
						//是序列号
						std::cout << "\tFirstThunk IMAGE_THUNK_DATA Hint:" << std::hex << IMAGE_ORDINAL(ith_tmp.u1.Ordinal) << std::endl;
					}
					else
					{
						//是 RVA
						PIMAGE_IMPORT_BY_NAME p_image_import_by_name = (PIMAGE_IMPORT_BY_NAME)((DWORDX)base + ith_tmp.u1.Ordinal - import_descriptor_offset);
						p_image_import_by_name->Hint; //本函数在其所驻留 DLL 的输出表中的序号
						p_image_import_by_name->Name; //输入函数的函数名

						std::cout << "\tFirstThunk IMAGE_THUNK_DATA IMAGE_IMPORT_BY_NAME Hint:" << std::hex << p_image_import_by_name->Hint << " Name:" << (const char*)p_image_import_by_name->Name << std::endl;
					}
					//std::cout << "\tFirstThunk IMAGE_THUNK_DATA :" << std::hex << ith_tmp.u1.Ordinal << std::endl;;
				}

			}
		}
	}

	//绑定输入
	//目录表的 12 个成员指向绑定输入 IMAGE_BOUND_IMPORT_DESCRIPTOR 每个绑定的结构都指出了一个被绑定输入 DLL 的时间/日期戳
	//PIMAGE_BOUND_IMPORT_DESCRIPTOR p_image_bound_import_descriptor_base;
	//DWORDX bound_import_descriptor_offset = 0;
	{
		PIMAGE_BOUND_IMPORT_DESCRIPTOR p_image_bound_import_descriptor_base = NULL;  //绑定输入表基地址
		DWORDX bound_import_descriptor_offset = 0;
		auto it = section_rva_2_offset_map.upper_bound(p_image_data_directory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress); --it;
		if (p_image_data_directory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != NULL && it != section_rva_2_offset_map.end())
		{
			bound_import_descriptor_offset = it->second;
			p_image_bound_import_descriptor_base = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORDX)base + p_image_data_directory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress - bound_import_descriptor_offset);

			PVOID p_void_tmp = (PVOID)p_image_bound_import_descriptor_base;
			while (1)
			{

				PIMAGE_BOUND_IMPORT_DESCRIPTOR tmp = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)p_void_tmp;
				tmp->TimeDateStamp;					//时间戳
				tmp->OffsetModuleName;				//名字偏移，基址是 IMAGE_BOUND_IMPORT_DESCRIPTOR 的开端
				tmp->NumberOfModuleForwarderRefs;	//后面 IMAGE_BOUND_FORWARDER_REF 结构的数量

				if (tmp->TimeDateStamp == NULL && tmp->OffsetModuleName == NULL && tmp->NumberOfModuleForwarderRefs == NULL) break;

				std::cout << "\tIMAGE_BOUND_IMPORT_DESCRIPTOR Time:" << tmp->TimeDateStamp << " Name:" << (const char*)((DWORDX)p_image_bound_import_descriptor_base + tmp->OffsetModuleName)
					<< " NumberOfModuleForwarderRefs:" << tmp->NumberOfModuleForwarderRefs << std::endl;

				//IMAGE_BOUND_FORWARDER_REF 结构体的内容跟上面的其实是差不多的，绑定导入表中有一个函数转发链机制
				//比如说 KERNEL32.DLL 里面的 HeapAlloc 函数会转发到 NTDLL.DLL 中的 RtlAllocateHeap 函数，一般情况下 NumberOfModuleForwarderRefs 为 0
				if (tmp->NumberOfModuleForwarderRefs > 0)
				{
					for (int i = 0; i < tmp->NumberOfModuleForwarderRefs; ++i)
					{
						p_void_tmp = (PVOID)((DWORDX)p_void_tmp + i * sizeof(IMAGE_BOUND_FORWARDER_REF));
						PIMAGE_BOUND_FORWARDER_REF p_ref = (PIMAGE_BOUND_FORWARDER_REF)p_void_tmp;
						p_ref->TimeDateStamp;	//引用时间戳
						p_ref->OffsetModuleName;//名字偏移
						p_ref->Reserved;		//保留

						std::cout << "\t\tIMAGE_BOUND_FORWARDER_REF Time:" << p_ref->TimeDateStamp << " Name:" << (const char*)((DWORDX)p_image_bound_import_descriptor_base + p_ref->OffsetModuleName) << std::endl;
					}
				}
				p_void_tmp = (PVOID)((DWORDX)p_void_tmp + sizeof(PIMAGE_BOUND_IMPORT_DESCRIPTOR));
			}

		}
	}


	//输出表
	//PIMAGE_EXPORT_DIRECTORY p_image_export_directory_base = NULL;	//导出表
	//DWORDX export_directory_offset = 0;
	{
		PIMAGE_EXPORT_DIRECTORY p_image_export_directory_base = NULL;	//导出表
		DWORDX export_directory_offset = 0;
		auto it = section_rva_2_offset_map.upper_bound(p_image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); --it;
		if (p_image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL && it != section_rva_2_offset_map.end())
		{
			export_directory_offset = it->second;
			p_image_export_directory_base = (PIMAGE_EXPORT_DIRECTORY)((DWORDX)base + p_image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - export_directory_offset);

			p_image_export_directory_base->Characteristics;			//没用到，一般为0
			p_image_export_directory_base->TimeDateStamp;			//生成的时间戳
			p_image_export_directory_base->MajorVersion;			//版本
			p_image_export_directory_base->MinorVersion;			//版本
			p_image_export_directory_base->Name;					//名字
			p_image_export_directory_base->Base;					//序列号的基数，按序列号导出函数的序号值从 Base 开始递增
			p_image_export_directory_base->NumberOfFunctions;		//所有导出函数的数量
			p_image_export_directory_base->NumberOfNames;			//按名字导出函数的数量
			p_image_export_directory_base->AddressOfFunctions;		//一个 RVA，指向一个 DWORD 数组，数组中的每一项是一个导出函数的 RVA，顺序与导出序号相同
			p_image_export_directory_base->AddressOfNames;			//一个 RVA，依然指向一个 DWORD 数组，数组中的每一项仍然是一个 RVA，指向一个表示函数名字
			p_image_export_directory_base->AddressOfNameOrdinals;	//一个 RVA，还是指向一个 WORD 数组，数组中的每一项与 AddressOfNames 中的每一项对应，
																	//表示该名字的函数在 AddressOfFunctions 中的序号

			std::cout << "IMAGE_EXPORT_DIRECTORY Name:" << (const char*)((DWORDX)base + p_image_export_directory_base->Name - export_directory_offset) <<
				" Base:" << p_image_export_directory_base->Base <<
				" NumberOfFunctions:" << p_image_export_directory_base->NumberOfFunctions <<
				" NumberOfNames:" << p_image_export_directory_base->NumberOfNames << std::endl;

			PDWORD tmp = (PDWORD)((DWORDX)base + p_image_export_directory_base->AddressOfFunctions - export_directory_offset);
			for (auto i = 0; i < p_image_export_directory_base->NumberOfFunctions; ++i)
			{
				auto it = section_rva_2_offset_map.upper_bound(tmp[i]); --it;
				if (it != section_rva_2_offset_map.end())
				{
					std::cout << "\tIMAGE_EXPORT_DIRECTORY AddressOfFunctions RVA:" << std::hex << (tmp[i]) << " ROffset:" << (tmp[i] - it->second) << std::endl;
				}
				else
				{
					std::cout << "\tIMAGE_EXPORT_DIRECTORY AddressOfFunctions RVA:" << std::hex << (tmp[i]) << " Unknown ROffset" << std::endl;
				}
			}

			tmp = (PDWORD)((DWORDX)base + p_image_export_directory_base->AddressOfNames - export_directory_offset);
			for (auto i = 0; i < p_image_export_directory_base->NumberOfNames; ++i)
			{
				std::cout << "\tIMAGE_EXPORT_DIRECTORY AddressOfNames:" << (const char*)((DWORDX)base + tmp[i] - export_directory_offset) << std::endl;
			}

			PWORD tmp_pword = (PWORD)((DWORDX)base + p_image_export_directory_base->AddressOfNameOrdinals - export_directory_offset);
			for (auto i = 0; i < p_image_export_directory_base->NumberOfNames; ++i)
			{
				std::cout << "\tIMAGE_EXPORT_DIRECTORY AddressOfNameOrdinals Index:" << std::hex << (tmp_pword[i]) << std::endl;

			}
		}

	}
	//基地址重定位
	//PIMAGE_EXPORT_DIRECTORY p_image_export_directory_base = NULL;	//导出表
	//DWORDX export_directory_offset = 0;
	{
		PIMAGE_BASE_RELOCATION p_image_base_relocation_base = NULL;	//导出表
		DWORDX base_relocation_offset = 0;
		auto it = section_rva_2_offset_map.upper_bound(p_image_data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress); --it;
		if (p_image_data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != NULL && it != section_rva_2_offset_map.end())
		{
			base_relocation_offset = it->second;
			p_image_base_relocation_base = (PIMAGE_BASE_RELOCATION)((DWORDX)base + p_image_data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress - base_relocation_offset);
			PIMAGE_BASE_RELOCATION p_tmp_reloc = p_image_base_relocation_base;

			while (true)
			{
				if (p_tmp_reloc->SizeOfBlock == NULL && p_tmp_reloc->VirtualAddress == NULL) break;

				p_tmp_reloc->VirtualAddress;	//重定位的 RVA
				p_tmp_reloc->SizeOfBlock;		//大小

				DWORDX foa = 0;
				auto it2 = section_rva_2_offset_map.upper_bound(p_tmp_reloc->VirtualAddress); --it2;
				if (it2 != section_rva_2_offset_map.end())
				{
					foa = p_tmp_reloc->VirtualAddress - it2->second;  //偏移
				}
				DWORDX size = (DWORDX)(p_tmp_reloc->SizeOfBlock - 8) / 2;
				std::cout << "IMAGE_BASE_RELOCATION VirtualAddress:" << std::hex << p_tmp_reloc->VirtualAddress << " SizeOfBlock:" << p_tmp_reloc->SizeOfBlock << " Size:"<< size << std::endl;

				PWORD p_rec_addr = (PWORD)((PBYTE)p_tmp_reloc + 8);
				for (DWORDX j = 0; j < size; ++j)
				{
					DWORDX rva = (p_rec_addr[j] & 0x0FFF) + p_tmp_reloc->VirtualAddress;
					DWORDX offset = (p_rec_addr[j] & 0x0FFF) + foa;//低四位是偏移地址
					WORD type = p_rec_addr[j] >> 12;  //高四位是有效判断位
					if (type == 0) continue;
					//TODO: 确认
					std::cout << "\t["<<j << "] rva: "<< rva <<" offset:" << offset << " type:"<<type<< std::endl;
				}
				p_tmp_reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)p_tmp_reloc + p_tmp_reloc->SizeOfBlock);
			}
		}

	}

	//资源
	//PIMAGE_RESOURCE_DIRECTORY p_image_resource_directory = NULL;
	//DWORDX resource_directory_offset = 0;
	{
		PIMAGE_RESOURCE_DIRECTORY p_image_resource_directory = NULL;
		DWORDX resource_directory_offset = 0;
		auto it = section_rva_2_offset_map.upper_bound(p_image_data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress); --it;
		if (p_image_data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != NULL && it != section_rva_2_offset_map.end())
		{
			resource_directory_offset = it->second;
			p_image_resource_directory = (PIMAGE_RESOURCE_DIRECTORY)((DWORDX)base + p_image_data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress - resource_directory_offset);

			PIMAGE_RESOURCE_DIRECTORY p_tmp_res = p_image_resource_directory;
			p_tmp_res->Characteristics;
			p_tmp_res->MajorVersion;
			p_tmp_res->MinorVersion;
			p_tmp_res->NumberOfNamedEntries;	// 用户自定义资源类型的个数
			p_tmp_res->NumberOfIdEntries;		// 典型资源例如位图，图标，对话框等资源类型的个数
			p_tmp_res->TimeDateStamp;

			std::cout << "IMAGE_RESOURCE_DIRECTORY NumberOfNamedEntries:" << p_tmp_res->NumberOfNamedEntries 
				<< " NumberOfIdEntries:" << p_tmp_res->NumberOfIdEntries << std::endl;

			PIMAGE_RESOURCE_DIRECTORY_ENTRY p_tmp_res_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORDX)p_tmp_res + sizeof(IMAGE_RESOURCE_DIRECTORY));
			for (auto i = 0; i < p_tmp_res->NumberOfNamedEntries + p_tmp_res->NumberOfIdEntries; ++i)
			{
				IMAGE_RESOURCE_DIRECTORY_ENTRY res_dir_entry = p_tmp_res_entry[i];
				if (res_dir_entry.NameIsString == 1)
				{
					std::cout << "\tName:" << res_dir_entry.NameOffset << std::endl;
				}
				else
				{
					std::cout << "\tID:" << std::dec << res_dir_entry.Id << std::endl;
				}
				if (res_dir_entry.DataIsDirectory == 1)
				{
					std::cout << "\tOffsetToDirectory:" << res_dir_entry.OffsetToDirectory << std::endl;
					PIMAGE_RESOURCE_DIRECTORY tmp = (PIMAGE_RESOURCE_DIRECTORY)((DWORDX)p_image_resource_directory + res_dir_entry.OffsetToDirectory);
					while (true)
					{
						break;
					}

				}
				else
				{
					std::cout << "\tOffsetToData:" << res_dir_entry.OffsetToData << std::endl;
				}
			}
		}

	}


	// TLS 初始化

	//调试目录

	//延迟载入数据

	//程序异常数据

	//.NET 头部



	return true;
}
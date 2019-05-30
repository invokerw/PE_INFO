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
	if (p_image_dos_header->e_magic != IMAGE_DOS_SIGNATURE)  //Dos ��ִ���ļ���� MZ  0x5A4D
	{
		std::cout << "NOT MZ" << std::endl;
		return false;
	}

	//p_image_dos_header->e_lfanew; PE �ļ�ͷƫ��
	//���� PIMAGE_NT_HEADERS �ڲ�ͬƽ̨�¶�Ӧ 32 λ PIMAGE_NT_HEADERS32��64 λ PIMAGE_NT_HEADERS64
	PIMAGE_NT_HEADERS p_image_nt_header = (PIMAGE_NT_HEADERS)((DWORDX)base + p_image_dos_header->e_lfanew);
	if(p_image_nt_header->Signature != IMAGE_NT_SIGNATURE) // PE ��ִ���ļ���� PE00  0x00004550
	{ 
		std::cout << "NOT PE" << std::endl;
		return false;
	}
	
	IMAGE_FILE_HEADER image_file_header = p_image_nt_header->FileHeader;
	// Machine �� IMAGE_FILE_MACHINE_*  
	image_file_header.Machine;			//��ִ���ļ���Ŀ�� CPU ����
	image_file_header.NumberOfSections;	//���� Section ����Ŀ
	image_file_header.TimeDateStamp;	//�ļ��Ĵ���ʱ��
	image_file_header.PointerToSymbolTable; // COFF ���ű���ļ�ƫ��λ��
	image_file_header.NumberOfSymbols;		// ����� COFF ���ű��������еķ�����Ŀ
	image_file_header.SizeOfOptionalHeader; // ���ݵĴ�С��32 λ�� 64 ���������32 ͨ���� 00E0h��64 ��Ϊ 00F0h
	image_file_header.Characteristics;		// �ļ�����, IMAGE_FILE_xxx EXE һ���� 010fh�� DLL һ���� 2102h

	//32 λ IMAGE_OPTIONAL_HEADER32��64 λ IMAGE_OPTIONAL_HEADER64
	IMAGE_OPTIONAL_HEADER image_optional_header = p_image_nt_header->OptionalHeader;
	image_optional_header.BaseOfCode; //�������ʼ RVA
	image_optional_header.ImageBase;  //�ļ����ڴ��е���ѡ�����ַ
	image_optional_header.SectionAlignment;	//�����ڴ�ʱ�����������С     0x1000
	image_optional_header.FileAlignment;	//�����ϵ� PE �ļ�����������С 0x200
	image_optional_header.SizeOfImage;		//ӳ�������ڴ����ܳߴ�
	image_optional_header.SizeOfHeaders;	//DOS ͷ��PE�ļ�ͷ���������ܳߴ�
	image_optional_header.CheckSum;			//У���
	image_optional_header.AddressOfEntryPoint; //Ҳ���������ᵽ��OEP������Դ��ڵ㡣
	
	image_optional_header.NumberOfRvaAndSizes; //����Ŀ¼���������� Windows NT ����һֱ��16... �Ҷ��������� 0
	PIMAGE_DATA_DIRECTORY p_image_data_directory = image_optional_header.DataDirectory;
	for (int i = 0;i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
	{
		p_image_data_directory[i].VirtualAddress;	//���ݿ����ʼ RVA
		p_image_data_directory[i].Size;				//���ݿ�ĳ���
		std::cout << "DataDirectory "<< 
			data_drictory_str[i].c_str()<<" VirtualAddress:" << std::hex << p_image_data_directory[i].VirtualAddress
			<< " Size:" << std::hex << p_image_data_directory[i].Size << std::endl;
	}
	
	std::map<DWORDX, DWORDX> section_rva_2_offset_map;  // section �����ַ VirtualAddress -> ƫ�� (tmp.VirtualAddress - tmp.PointerToRawData)

	//����
	PIMAGE_SECTION_HEADER p_image_section_header_base = (PIMAGE_SECTION_HEADER)((DWORDX)p_image_nt_header + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < image_file_header.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER tmp = p_image_section_header_base[i];
		tmp.Name;				//8 �ֽڿ���
		tmp.Misc.VirtualSize;	//ʵ��ʹ�õ������С�����봦��ǰ
		tmp.VirtualAddress;		//װ�����ڴ��е� RVA
		tmp.SizeOfRawData;		//�ڴ�������ռ�Ŀռ�
		tmp.PointerToRawData;	//�ڴ����ļ��е�ƫ��
		tmp.Characteristics;	//������ �ɶ���д��ִ�е�

		section_rva_2_offset_map[tmp.VirtualAddress] = tmp.VirtualAddress - tmp.PointerToRawData;


		std::cout << "Section Name:" << (const char*)tmp.Name << 
			" VirtualSize:"<< std::hex <<tmp.Misc.VirtualSize <<
			" VirtualAddress:" << std::hex << tmp.VirtualAddress <<
			" SizeOfRawData:" << std::hex << tmp.SizeOfRawData <<
			" PointerToRawData:" << std::hex << tmp.PointerToRawData <<
			" Characteristics:" << std::hex << tmp.Characteristics << std::endl;
		
	}

	//�����  p_image_nt_header->OptionalHeader.DataDirectory[1] ��� �ڶ���
	//PIMAGE_IMPORT_DESCRIPTOR p_image_import_descriptor_base
	//DWORDX import_descriptor_offset = 0;
	{
		PIMAGE_IMPORT_DESCRIPTOR p_image_import_descriptor_base = NULL;  //��������ַ
		DWORDX import_descriptor_offset = 0;

		auto it = section_rva_2_offset_map.upper_bound(p_image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); --it;
		if (p_image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL && it != section_rva_2_offset_map.end())
		{
			import_descriptor_offset = it->second;
			p_image_import_descriptor_base = (PIMAGE_IMPORT_DESCRIPTOR)((DWORDX)base + p_image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - import_descriptor_offset);

			for (int i = 0;;++i)
			{
				IMAGE_IMPORT_DESCRIPTOR tmp = p_image_import_descriptor_base[i];
				tmp.OriginalFirstThunk; //ָ���������Ʊ�(INT)��RVA IMAGE_THUNK_DATA  ���ɸ�д
				tmp.TimeDateStamp;		//ʱ���־
				tmp.ForwarderChain;		//��һ����ת��� API ����,һ��Ϊ 0���ڳ�������һ�� DLL �е� API����� API ���������� DLL �� API ʹ��
				tmp.Name;				//DLL ����ָ��
				tmp.FirstThunk;			//ָ�������ַ��(IAT)�� RVA, IMAGE_THUNK_DATA �����飬PE װ������д
				if (tmp.Name == NULL) break;

				std::cout << "IMPORT_DESCRIPTOR Name:" << (const char*)((DWORDX)base + tmp.Name - import_descriptor_offset) << std::endl;

				PIMAGE_THUNK_DATA p_oft_base = (PIMAGE_THUNK_DATA)((DWORDX)base + tmp.OriginalFirstThunk - import_descriptor_offset);
				for (int j = 0;; ++j)
				{
					IMAGE_THUNK_DATA ith_tmp = p_oft_base[j];
					if(ith_tmp.u1.ForwarderString == NULL) break;
					if (IMAGE_SNAP_BY_ORDINAL(ith_tmp.u1.Ordinal))
					{
						//�����к�
						//std::cout << "\tIMAGE_THUNK_DATA Hint:" << std::hex << IMAGE_ORDINAL(ith_tmp.u1.Ordinal) << std::endl;
					}
					else
					{
						//�� RVA
						PIMAGE_IMPORT_BY_NAME p_image_import_by_name = (PIMAGE_IMPORT_BY_NAME)((DWORDX)base + ith_tmp.u1.Ordinal - import_descriptor_offset);
						p_image_import_by_name->Hint; //������������פ�� DLL ��������е����
						p_image_import_by_name->Name; //���뺯���ĺ�����

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
						//�����к�
						std::cout << "\tFirstThunk IMAGE_THUNK_DATA Hint:" << std::hex << IMAGE_ORDINAL(ith_tmp.u1.Ordinal) << std::endl;
					}
					else
					{
						//�� RVA
						PIMAGE_IMPORT_BY_NAME p_image_import_by_name = (PIMAGE_IMPORT_BY_NAME)((DWORDX)base + ith_tmp.u1.Ordinal - import_descriptor_offset);
						p_image_import_by_name->Hint; //������������פ�� DLL ��������е����
						p_image_import_by_name->Name; //���뺯���ĺ�����

						std::cout << "\tFirstThunk IMAGE_THUNK_DATA IMAGE_IMPORT_BY_NAME Hint:" << std::hex << p_image_import_by_name->Hint << " Name:" << (const char*)p_image_import_by_name->Name << std::endl;
					}
					//std::cout << "\tFirstThunk IMAGE_THUNK_DATA :" << std::hex << ith_tmp.u1.Ordinal << std::endl;;
				}

			}
		}
	}

	//������
	//Ŀ¼��� 12 ����Աָ������� IMAGE_BOUND_IMPORT_DESCRIPTOR ÿ���󶨵Ľṹ��ָ����һ���������� DLL ��ʱ��/���ڴ�
	//PIMAGE_BOUND_IMPORT_DESCRIPTOR p_image_bound_import_descriptor_base;
	//DWORDX bound_import_descriptor_offset = 0;
	{
		PIMAGE_BOUND_IMPORT_DESCRIPTOR p_image_bound_import_descriptor_base = NULL;  //����������ַ
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
				tmp->TimeDateStamp;					//ʱ���
				tmp->OffsetModuleName;				//����ƫ�ƣ���ַ�� IMAGE_BOUND_IMPORT_DESCRIPTOR �Ŀ���
				tmp->NumberOfModuleForwarderRefs;	//���� IMAGE_BOUND_FORWARDER_REF �ṹ������

				if (tmp->TimeDateStamp == NULL && tmp->OffsetModuleName == NULL && tmp->NumberOfModuleForwarderRefs == NULL) break;

				std::cout << "\tIMAGE_BOUND_IMPORT_DESCRIPTOR Time:" << tmp->TimeDateStamp << " Name:" << (const char*)((DWORDX)p_image_bound_import_descriptor_base + tmp->OffsetModuleName)
					<< " NumberOfModuleForwarderRefs:" << tmp->NumberOfModuleForwarderRefs << std::endl;

				//IMAGE_BOUND_FORWARDER_REF �ṹ������ݸ��������ʵ�ǲ��ģ��󶨵��������һ������ת��������
				//����˵ KERNEL32.DLL ����� HeapAlloc ������ת���� NTDLL.DLL �е� RtlAllocateHeap ������һ������� NumberOfModuleForwarderRefs Ϊ 0
				if (tmp->NumberOfModuleForwarderRefs > 0)
				{
					for (int i = 0; i < tmp->NumberOfModuleForwarderRefs; ++i)
					{
						p_void_tmp = (PVOID)((DWORDX)p_void_tmp + i * sizeof(IMAGE_BOUND_FORWARDER_REF));
						PIMAGE_BOUND_FORWARDER_REF p_ref = (PIMAGE_BOUND_FORWARDER_REF)p_void_tmp;
						p_ref->TimeDateStamp;	//����ʱ���
						p_ref->OffsetModuleName;//����ƫ��
						p_ref->Reserved;		//����

						std::cout << "\t\tIMAGE_BOUND_FORWARDER_REF Time:" << p_ref->TimeDateStamp << " Name:" << (const char*)((DWORDX)p_image_bound_import_descriptor_base + p_ref->OffsetModuleName) << std::endl;
					}
				}
				p_void_tmp = (PVOID)((DWORDX)p_void_tmp + sizeof(PIMAGE_BOUND_IMPORT_DESCRIPTOR));
			}

		}
	}


	//�����
	//PIMAGE_EXPORT_DIRECTORY p_image_export_directory_base = NULL;	//������
	//DWORDX export_directory_offset = 0;
	{
		PIMAGE_EXPORT_DIRECTORY p_image_export_directory_base = NULL;	//������
		DWORDX export_directory_offset = 0;
		auto it = section_rva_2_offset_map.upper_bound(p_image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); --it;
		if (p_image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL && it != section_rva_2_offset_map.end())
		{
			export_directory_offset = it->second;
			p_image_export_directory_base = (PIMAGE_EXPORT_DIRECTORY)((DWORDX)base + p_image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - export_directory_offset);

			p_image_export_directory_base->Characteristics;			//û�õ���һ��Ϊ0
			p_image_export_directory_base->TimeDateStamp;			//���ɵ�ʱ���
			p_image_export_directory_base->MajorVersion;			//�汾
			p_image_export_directory_base->MinorVersion;			//�汾
			p_image_export_directory_base->Name;					//����
			p_image_export_directory_base->Base;					//���кŵĻ����������кŵ������������ֵ�� Base ��ʼ����
			p_image_export_directory_base->NumberOfFunctions;		//���е�������������
			p_image_export_directory_base->NumberOfNames;			//�����ֵ�������������
			p_image_export_directory_base->AddressOfFunctions;		//һ�� RVA��ָ��һ�� DWORD ���飬�����е�ÿһ����һ������������ RVA��˳���뵼�������ͬ
			p_image_export_directory_base->AddressOfNames;			//һ�� RVA����Ȼָ��һ�� DWORD ���飬�����е�ÿһ����Ȼ��һ�� RVA��ָ��һ����ʾ��������
			p_image_export_directory_base->AddressOfNameOrdinals;	//һ�� RVA������ָ��һ�� WORD ���飬�����е�ÿһ���� AddressOfNames �е�ÿһ���Ӧ��
																	//��ʾ�����ֵĺ����� AddressOfFunctions �е����

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
	//����ַ�ض�λ
	//PIMAGE_EXPORT_DIRECTORY p_image_export_directory_base = NULL;	//������
	//DWORDX export_directory_offset = 0;
	{
		PIMAGE_BASE_RELOCATION p_image_base_relocation_base = NULL;	//������
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

				p_tmp_reloc->VirtualAddress;	//�ض�λ�� RVA
				p_tmp_reloc->SizeOfBlock;		//��С

				DWORDX foa = 0;
				auto it2 = section_rva_2_offset_map.upper_bound(p_tmp_reloc->VirtualAddress); --it2;
				if (it2 != section_rva_2_offset_map.end())
				{
					foa = p_tmp_reloc->VirtualAddress - it2->second;  //ƫ��
				}
				DWORDX size = (DWORDX)(p_tmp_reloc->SizeOfBlock - 8) / 2;
				std::cout << "IMAGE_BASE_RELOCATION VirtualAddress:" << std::hex << p_tmp_reloc->VirtualAddress << " SizeOfBlock:" << p_tmp_reloc->SizeOfBlock << " Size:"<< size << std::endl;

				PWORD p_rec_addr = (PWORD)((PBYTE)p_tmp_reloc + 8);
				for (DWORDX j = 0; j < size; ++j)
				{
					DWORDX rva = (p_rec_addr[j] & 0x0FFF) + p_tmp_reloc->VirtualAddress;
					DWORDX offset = (p_rec_addr[j] & 0x0FFF) + foa;//����λ��ƫ�Ƶ�ַ
					WORD type = p_rec_addr[j] >> 12;  //����λ����Ч�ж�λ
					if (type == 0) continue;
					//TODO: ȷ��
					std::cout << "\t["<<j << "] rva: "<< rva <<" offset:" << offset << " type:"<<type<< std::endl;
				}
				p_tmp_reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)p_tmp_reloc + p_tmp_reloc->SizeOfBlock);
			}
		}

	}

	//��Դ
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
			p_tmp_res->NumberOfNamedEntries;	// �û��Զ�����Դ���͵ĸ���
			p_tmp_res->NumberOfIdEntries;		// ������Դ����λͼ��ͼ�꣬�Ի������Դ���͵ĸ���
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


	// TLS ��ʼ��

	//����Ŀ¼

	//�ӳ���������

	//�����쳣����

	//.NET ͷ��



	return true;
}
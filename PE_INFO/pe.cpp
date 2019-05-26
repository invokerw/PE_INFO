#include "pe.h"

#include <Winternl.h>
#include <iostream>

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
	
	PIMAGE_IMPORT_DESCRIPTOR p_image_import_descriptor_base = NULL;  //��������ַ
	DWORDX import_descriptor_offset = 0;

	//����
	PIMAGE_SECTION_HEADER p_image_section_header_base = (PIMAGE_SECTION_HEADER)((DWORDX)p_image_nt_header + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < image_file_header.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER tmp = p_image_section_header_base[i];
		tmp.Name;				//8 �ֽڿ���
		tmp.Misc.VirtualSize;	//ʵ��ʹ�õ������С�����봦��ǰ
		tmp.VirtualAddress;	//װ�����ڴ��е� RVA
		tmp.SizeOfRawData;		//�ڴ�������ռ�Ŀռ�
		tmp.PointerToRawData;	//�ڴ����ļ��е�ƫ��
		tmp.Characteristics;	//������ �ɶ���д��ִ�е�

		if (!p_image_import_descriptor_base && p_image_data_directory[1].VirtualAddress >= tmp.VirtualAddress
			&& p_image_data_directory[1].VirtualAddress + p_image_data_directory[1].Size <= tmp.VirtualAddress + tmp.Misc.VirtualSize)
		{
			// ���������һ�����, �����������ļ�ƫ��
			import_descriptor_offset = tmp.VirtualAddress - tmp.PointerToRawData;
			p_image_import_descriptor_base = (PIMAGE_IMPORT_DESCRIPTOR)((DWORDX)base + p_image_data_directory[1].VirtualAddress - import_descriptor_offset);
		}

		std::cout << "Section Name:" << (const char*)tmp.Name << 
			" VirtualSize:"<< std::hex <<tmp.Misc.VirtualSize <<
			" VirtualAddress:" << std::hex << tmp.VirtualAddress <<
			" SizeOfRawData:" << std::hex << tmp.SizeOfRawData <<
			" PointerToRawData:" << std::hex << tmp.PointerToRawData <<
			" Characteristics:" << std::hex << tmp.Characteristics << std::endl;
		
	}

	//�����  p_image_nt_header->OptionalHeader.DataDirectory[1] ��� �ڶ���
	//Ŀ¼��� 12 ����Աָ������� IMAGE_BOUND_IMPORT_DESCRIPTOR ÿ���󶨵Ľṹ��ָ����һ���������� DLL ��ʱ��/���ڴ�

	//PIMAGE_IMPORT_DESCRIPTOR p_image_import_descriptor_base
	for (int i = 0;;++i)
	{
		IMAGE_IMPORT_DESCRIPTOR tmp = p_image_import_descriptor_base[i];
		tmp.OriginalFirstThunk; //ָ���������Ʊ�(INT)��RVA IMAGE_THUNK_DATA  ���ɸ�д
		tmp.TimeDateStamp;		//ʱ���־
		tmp.ForwarderChain;		//��һ����ת��� API ����,һ��Ϊ 0���ڳ�������һ�� DLL �е� API����� API ���������� DLL �� API ʹ��
		tmp.Name;				//DLL ����ָ��
		tmp.FirstThunk;			//ָ�������ַ��(IAT)�� RVA, IMAGE_THUNK_DATA �����飬PE װ������д
		if (tmp.Name == NULL) break;

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

		std::cout << "IMPORT_DESCRIPTOR Name:" << (const char*)((DWORDX)base + tmp.Name - import_descriptor_offset)  << std::endl;
	}

	//������

	//�����

	//����ַ�ض�λ

	//��Դ

	// TLS ��ʼ��

	//����Ŀ¼

	//�ӳ���������

	//�����쳣����

	//.NET ͷ��



	return true;
}
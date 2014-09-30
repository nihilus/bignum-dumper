#pragma once

#define _MKN(c) #c
#define _MKC(s, id) s #id

//A - ascii string                                char* at least MAXSTR size
#define CMD_ASCII(id)	_MKC("A", id)
//S - segment                                     sel_t*
#define CMD_SEGMENT(id) _MKC("S", id)
//N - hex number, C notation                      uval_t*
#define CMD_HEXNUM(id)	_MKC("N", id)
//n - signed hex number, C notation               sval_t*
#define CMD_SHEXNUM(id) _MKC("n", id)
//L - default base( usually hex ) number, uint64*
//C notation
#define CMD_BASE(id)	_MKC("L", id)
//l - default base( usually hex ) number, signed, int64*
//C notation
#define CMD_SBASE(id)	_MKC("l", id)
//M - hex number, no "0x" prefix                  uval_t*
#define CMD_BAREHEX(id) _MKC("M", id)
//D - decimal number                              sval_t*
#define CMD_DEC(id) _MKC("D", id)
//O - octal number, C notation                    sval_t*
#define CMD_OCT(id) _MKC("O", id)
//Y - binary number, "0b" prefix                  sval_t*
#define CMD_BIN(id) _MKC("Y", id)
//H - char value, C notation                      sval_t*
#define CMD_CHAR(id) _MKC("H", id)
//$ - address                                     ea_t*
#define CMD_ADDR(id) _MKC("$", id)
//I - ident                                       char* at least MAXNAMELEN size
#define CMD_IDENT(id) _MKC("I", id)
//B - button                                      formcb_t
#define CMD_BUTTON(id) _MKC("B", id)
//k - txt: button( same as B ) / gui : hyperlink      formcb_t
#define CMD_LINK(id) _MKC("k", id)
//K - color button                                bgcolor_t*
#define CMD_COLOR_BUTTON(id) _MKC("K", id)
//F - path to folder                              char* at least QMAXPATH size
#define CMD_PATH_FOLDER(id) _MKC("F", id)
//f - path to file                                char* at least QMAXPATH size
#define CMD_PATH_FILE(id) _MKC("f", id)

//T - type declaration                            char* at least MAXSTR size
#define CMD_TYPE(id) _MKC("T", id)

//E - chooser                                     chooser_info_t * -Embedded chooser
//intvec_t * -in / out: selected lines
//( NB : this field takes two args )
#define CMD_CHOOSE(id) _MKC("E", id)

//t - multi line text control                     textctrl_info_t *
#define CMD_TEXT_MULT(id) _MKC("t", id)

//b - dropdown list                               qstrvec_t * -the list of items
//int* or qstring* -the preselected item
//( qstring* when the combo is editable, i.e.width field is >0 )
#define CMD_DROPDOWN(id) _MKC("b", id)
//% - dynamic label
#define CMD_LABELA(id) "%" _MKN(id) "A"

/* ddfml.cpp - DDF Markup Language parser

   (c) 1997-2000 The Ohio State University

   Scott Cantor
   4/25/97

   $History: ddfml.cpp $
 * 
 * *****************  Version 28  *****************
 * User: Cantor       Date: 9/06/00    Time: 3:57p
 * Updated in $/NSAPI/ddfsvc
 * Added new list bounding options.
 * 
 * *****************  Version 27  *****************
 * User: Cantor       Date: 7/28/00    Time: 11:42p
 * Updated in $/NSAPI/ddfsvc
 * Added inverse conditional.
 * 
 * *****************  Version 26  *****************
 * User: Cantor       Date: 2/04/00    Time: 12:06a
 * Updated in $/NSAPI/ddfsvc
 * Added <new> header.
 * 
 * *****************  Version 25  *****************
 * User: Cantor       Date: 1/15/00    Time: 1:38a
 * Updated in $/NSAPI/ddfsvc
 * More STL updates.
 * 
 * *****************  Version 24  *****************
 * User: Cantor       Date: 1/07/00    Time: 6:46p
 * Updated in $/NSAPI/ddfsvc
 * Some strcmp corrections.
 * 
 * *****************  Version 23  *****************
 * User: Cantor       Date: 11/03/99   Time: 1:33p
 * Updated in $/NSAPI/ddfsvc
 * Added literal member output for members containing HTML.
 * 
 * *****************  Version 22  *****************
 * User: Cantor       Date: 10/08/99   Time: 11:33a
 * Updated in $/NSAPI/ddfsvc
 * Stopped encoding spaces.
 * 
 * *****************  Version 21  *****************
 * User: Cantor       Date: 10/08/99   Time: 11:29a
 * Updated in $/NSAPI/ddfsvc
 * Added HTML entity encoding of member output.
 *
 * *****************  Version 20  *****************
 * User: Cantor       Date: 10/07/99   Time: 2:29p
 * Updated in $/NSAPI/ddfsvc
 * Fixed abort tag to cause true abort rather than break semantics.
 * 
 * *****************  Version 19  *****************
 * User: Cantor       Date: 9/19/99    Time: 3:13p
 * Updated in $/NSAPI/ddfsvc
 * Added int/struct/list output support.
 * 
 * *****************  Version 18  *****************
 * User: Cantor       Date: 9/17/99    Time: 11:33a
 * Updated in $/NSAPI/ddfsvc
 * Added struct support for DDF LIST tag.
 * 
 * *****************  Version 17  *****************
 * User: Cantor       Date: 8/27/99    Time: 2:56p
 * Updated in $/NSAPI/ddfsvc
 * Update of code base.
 * 
 * *****************  Version 16  *****************
 * User: Cantor       Date: 5/12/99    Time: 3:02p
 * Updated in $/NSAPI/ddfsvc
 * Added DOWNBLOCK construct.
 * 
 * *****************  Version 15  *****************
 * User: Cantor       Date: 4/26/99    Time: 10:45p
 * Updated in $/NSAPI/ddfsvc
 * Minor bug fix.
 * 
 * *****************  Version 14  *****************
 * User: Cantor       Date: 4/26/99    Time: 10:29p
 * Updated in $/NSAPI/ddfsvc
 * Modified conditional tag to assume second operand may be a DDF member.
 * 
 * *****************  Version 13  *****************
 * User: Cantor       Date: 10/13/98   Time: 5:46p
 * Updated in $/NSAPI/ddfsvc
 * Fixed conditional FILE constructs.
 * 
 * *****************  Version 12  *****************
 * User: Cantor       Date: 10/12/98   Time: 9:58a
 * Updated in $/NSAPI/ddfsvc
 * Added FILE inclusion support.
 * 
 * *****************  Version 8  *****************
 * User: Cantor       Date: 8/07/98    Time: 6:23p
 * Updated in $/NSAPI/ddfsvc
 * Completed up/down/if tag support.
 * 
 * *****************  Version 7  *****************
 * User: Cantor       Date: 7/30/98    Time: 6:16p
 * Updated in $/NSAPI/ddfsvc
 * Revamped parser and added support for structure navigation and
 * conditional checking. Also fixed nesting bugs and prepared for future
 * additions.
 * 
 * *****************  Version 5  *****************
 * User: Cantor       Date: 2/19/98    Time: 3:45p
 * Updated in $/NSAPI/ddfsvc
 * Removed backslash path separator option.
 * 
 * *****************  Version 4  *****************
 * User: Cantor       Date: 12/03/97   Time: 12:45p
 * Updated in $/NSAPI/ddfsvc
 * Added stdio.h.
 * 
 * *****************  Version 3  *****************
 * User: Cantor       Date: 10/30/97   Time: 4:46p
 * Updated in $/NSAPI/ddfsvc
 * Added multi-version support for NSAPI.
 * 
 * *****************  Version 2  *****************
 * User: Cantor       Date: 8/01/97    Time: 2:47p
 * Updated in $/NSAPI/ddfsvc
 * Fixed CString bug in parser.
 */

// Define NSAPI_OFF to remove NSAPI dependencies.

#include <new>
#include <string>
#include <ctime>
using namespace std;

#ifdef WIN32
# ifndef NSAPI_OFF
#  define XP_WIN32
#  define DDFSVC_EXPORT __declspec(dllexport)
# else
#  define util_strcasecmp stricmp
# endif
# include <windows.h>
#else
# ifndef NSAPI_OFF
#  define XP_UNIX
# endif
# define util_strcasecmp strcasecmp
# include <hresult.h>
# include <sys/mman.h>
# include <limits.h>
#endif

// These apparently work for NT now too.
#define PATH_SEP '/'
#define PATH_SEP_STRING "/"

#ifndef NSAPI_OFF
# define MCC_HTTPD
extern "C"
{
#include <nsapi.h>
}
# include <sockbuf.h>
#else
# include <stdio.h>
# define FREE free
# define REALLOC realloc
#endif

#include <cppddf.h>
#include <app_hresult.h>
#include <ddfsvc_status.h>

extern string g_DDFMLTemplateRoot;
DDFSVC_EXPORT HRESULT __stdcall ddfml_parse(CDDF obj, LPCSTR pathname
#ifndef NSAPI_OFF
                                            ,Session* sn, Request* rq
#endif
                                        );

// utility function to act as strstr for arbitrary terminated buffer
const char* bufstr(const char* buf, const char* str, size_t len)
{
    const char* cp=buf;
    const char* end=buf+len-1;
    const char* b;
    const char* s;

    while (len)
    {
        b=cp;
        s=str;
        while (b<end && toupper(*b)==toupper(*s))
            b++, s++;
        if (*s=='\0')
            return cp;
        cp++;
        len--;
    }
    return NULL;
}

// utility function like bufstr, but search is reversed. str must also be reversed.
const char* bufrstr(const char* buf, const char* str, size_t len)
{
    const char* start=buf;
    const char* end=buf+len-1;
    const char* b;
    const char* s;

    while (len)
    {
        b=end;
        s=str;
        while (b>=start && toupper(*b)==toupper(*s))
            b--, s++;
        if (*s=='\0')
            return end;
        end--;
        len--;
    }
    return NULL;
}

/* This package parses a DDFML template file, performs the appropriate data
   substitutions, and then writes the resulting file to an NSAPI socket.
   DDF markup can appear anywhere in a file, and all data outside the markup
   tags is echoed unchanged. All block constructs may be nested to any depth.

   The following constructs are supported:

   DDF members
        Members are named struct member designations that are replaced with the
        string value of the designated member.
        
   DDF lists
        Lists signify iteration over a body of data using an optionally named
        list. The body will normally contain member or list markup.
        
   DDF list indices
        List indices are replaced by the list index currently being processed,
        based from one.
        
   DDF structure navigation
        Structure navigation is used to descend into a structure for convenience
        of notation.
   
   DDF parent navigation
        Parent navigation traverses up the parent chain one step.

   DDF conditional member checking
        Conditional checking allows a block to be optionally parsed based on the
        existence of a member.

   DDF date/time insertion
        Insert current date/time with formatting.

   DDF abort
        Aborts parsing of document.

   DDF file inclusion
        Inserts a second template into the stream.
   
   Member:  <DDF in.ssn> or <DDF "in.name with spaces">
   List:    <DDF LIST in.list> or <DDF LIST> (block)
   Index:   <DDF INDEX>
   Descend: <DDF DOWN out> or <DDF DOWNBLOCK out>
   Parent:  <DDF UP 1> or <DDF UPBLOCK 1> (block)
   If:      <DDF IF in.ssn EQ 123456789> (block)
   Date:    <DDF TIME "%m/%d/%y">
   Abort:   <DDF ABORT>
   File:    <DDF FILE second_template.ddfml>
   Literal: <DDF LITERAL out.comment>

   Block tags open a block that is ended with </DDF>.
   
   Only the primary markup is actually parsed, using the following grammar: 

    0) <attrs> := <member>
    1)         := LIST <member> <member> <member>
    2)         := INDEX
    3)         := DOWN <member>
    4)         := DOWNBLOCK <member>
    5)         := UP <member>
    6)         := UPBLOCK <member>
    7)         := IF <member_name> <condexp>
    8)         := IFNOT <member_name> <condexp>
    9)         := TIME <member_name>
   10)         := ABORT
   11)         := FILE <member_name>
   12)         := LITERAL <member_name>
   13) <condexp> := <condop> <member_name>
   14)           := empty
   15) <condop> := EQ | NE | GT | LT | GE | LE
   16) <member> := <member_name>
   17)          := empty
   18) <member_name> := any sequence of non white-space but > OR
                        "any sequence of characters but quote or >"

   Keywords are not case sensitive.
*/

// token classes
enum ddfml_tokenclass {list_key, index_key, down_key, downblock_key, up_key, upblock_key, if_key,
                       ifnot_key, time_key, abort_key, file_key, literal_key, condop, member_name,
                       eof};

// symbolic symbol values
enum ddfml_symbol {null_sym, eq_sym, ne_sym, gt_sym, lt_sym, ge_sym, le_sym};

// non-terminals
#define NONTERM_START 15
enum ddfml_nonterminal {attrs=NONTERM_START, condexp, member};
#define istoken(a) (a<NONTERM_START)

// scanner states
enum ddfml_state {start, name_or_key, quoted_name, quoted_end};

#define RULE_START 18
#define isrule(a) (a>=RULE_START)
enum ddfml_rule {member_rule=RULE_START, list_rule, index_rule, down_rule, downblock_rule,
                 up_rule, upblock_rule, if_rule, ifnot_rule, time_rule, abort_rule, file_rule,
                 literal_rule, condexp_rule, condexp_empty_rule, member_name_rule, member_empty_rule};

// scan table (-1 means end of token)
static short scan_table[][5]=
{//                  alphanum     quote        whitespace   other
/* start        */ { name_or_key, quoted_name, start,       name_or_key},
/* name_or_key  */ { name_or_key, name_or_key, -1,          name_or_key},
/* quoted_name  */ { quoted_name, quoted_end,  quoted_name, quoted_name},
/* quoted_end   */ { -1,          -1,          -1,          -1},
};

// scanner is implemented as a class for reentrancy
class CScanner
{
public:
    CScanner() { m_start=m_end=NULL; }
    void init(LPCSTR start, LPCSTR end) { m_start=start; m_end=end; }

    bool get_token(ddfml_tokenclass& tokclass, string& tokstr);

private:
    short classify(char ch);
    bool change_state(ddfml_state& state, char ch);
    void map_to_class(ddfml_state state, ddfml_tokenclass& tokclass, string& tokstr);

    LPCSTR m_start;
    LPCSTR m_end;
};

// classify character into scan table column
short CScanner::classify(char ch)
{
    if (isalnum(ch))
        return 0;
    else if (isspace(ch))
        return 2;
    else if (ch=='"')
        return 1;
    else
        return 3;
}

// change scanner state
bool CScanner::change_state(ddfml_state& state, char ch)
{
    short s;

    if ((s=scan_table[state][classify(ch)])!=-1)
    {
        state=(ddfml_state)s;
        return true;
    }
    return false;
}

// determine class of token based on state and buffer
void CScanner::map_to_class(ddfml_state state,
                            ddfml_tokenclass& tokclass,
                            string& tokstr)
{
    switch (state)
    {
        case name_or_key:
            if (tokstr=="LIST")
                tokclass=list_key;
            else if (tokstr=="INDEX")
                tokclass=index_key;
            else if (tokstr=="DOWN")
                tokclass=down_key;
            else if (tokstr=="DOWNBLOCK")
                tokclass=downblock_key;
            else if (tokstr=="UP")
                tokclass=up_key;
            else if (tokstr=="UPBLOCK")
                tokclass=upblock_key;
            else if (tokstr=="IF")
                tokclass=if_key;
            else if (tokstr=="IFNOT")
                tokclass=ifnot_key;
            else if (tokstr=="TIME")
                tokclass=time_key;
            else if (tokstr=="ABORT")
                tokclass=abort_key;
            else if (tokstr=="FILE")
                tokclass=file_key;
            else if (tokstr=="LITERAL")
                tokclass=literal_key;
            else if (tokstr=="EQ" || tokstr=="NE" || tokstr=="GT" ||
                     tokstr=="LT" || tokstr=="GE" || tokstr=="LE")
                tokclass=condop;
            else
                tokclass=member_name;
            break;
        case quoted_end:
            tokclass=member_name;
            break;
        case start:
            tokclass=eof;
    }
}

// get the next token
bool CScanner::get_token(ddfml_tokenclass& tokclass, string& tokstr)
{
    // Clear token and goto start state.
    tokstr.erase();
    ddfml_state state=start;

    while (TRUE)
    {
        // Nothing left in string.  Map to state (possibly eof).
        if (m_start==m_end)
        {
            if (state==quoted_name)
                return FALSE;
            map_to_class(state,tokclass,tokstr);
            return TRUE;
        }

        // Try a state transition.
        if (change_state(state,*m_start))
        {
            // If in the middle of a string, stuff char in buffer.
            if (state==name_or_key || (state==quoted_name && *m_start!='"'))
                tokstr+=(*m_start);
            m_start++;
        }
        else if (state!=quoted_name)    // list of non-accepting states
        {
            // Token is complete, and valid.
            map_to_class(state,tokclass,tokstr);
            return TRUE;
        }
        else
            return FALSE;
    }
}

// parse table (-1 means no transition)
static short parse_table[][NONTERM_START]=
{//            LIST       INDEX       DOWN       DOWNBLOCK       UP       UPBLOCK       IF       IFNOT       TIME       ABORT       FILE       LITERAL,      condop        member_name       eof
/* attrs  */ { list_rule, index_rule, down_rule, downblock_rule, up_rule, upblock_rule, if_rule, ifnot_rule, time_rule, abort_rule, file_rule, literal_rule, -1,           member_rule,      member_rule},
/* condexp*/ { -1,        -1,         -1,        -1,             -1,      -1,           -1,      -1,         -1,        -1,         -1,        -1,           condexp_rule, -1,               condexp_empty_rule},
/* member */ { -1,        -1,         -1,        -1,             -1,      -1,           -1,      -1,         -1,        -1,         -1,        -1,           -1,           member_name_rule, member_empty_rule},
};

// rules table (-1 ends rule)
static short rules_table[][5]=
{
    { member,      -1,            -1,             -1,           -1},
    { member,      member,        member,         list_key,     -1},
    { index_key,   -1,            -1,             -1,           -1},
    { member,      down_key,      -1,             -1,           -1},
    { member,      downblock_key, -1,             -1,           -1},
    { member,      up_key,        -1,             -1,           -1},
    { member,      upblock_key,   -1,             -1,           -1},
    { condexp,     member_name,   if_key,         -1,           -1},
    { condexp,     member_name,   ifnot_key,      -1,           -1},
    { member_name, time_key,      -1,             -1,           -1},
    { abort_key,   -1,            -1,             -1,           -1},
    { member_name, file_key,      -1,             -1,           -1},
    { member_name, literal_key,   -1,             -1,           -1},
    { member_name, condop,        -1,             -1,           -1},
    { -1,          -1,            -1,             -1,           -1},
    { member_name, -1,            -1,             -1,           -1},
    { -1,          -1,            -1,             -1,           -1}
};

// parser class declaration
class CParser
{
public:
#ifndef NSAPI_OFF
    CParser(Session* sn, Request* rq) : m_sb(sn->csd)
        { m_sn=sn; m_rq=rq; }
private:
    CSockBuf m_sb;
    Session* m_sn;
    Request* m_rq;
public:
#endif
    HRESULT process_file_section(CDDF obj,
                                 unsigned long index,
                                 LPCSTR start,
                                 LPCSTR end,
                                 LPCSTR& block_end,
                                 unsigned long ulNestLevel=0,
                                 bool bEatInput=false);

    HRESULT flush() { return (IO_ERROR==m_sb.flush()) ? DDFML_E_NETIO : NOERROR; }

private:
    HRESULT parse(LPCSTR start, LPCSTR end);

    CScanner m_scanner;
    string m_tokstr;

    // stored off by parse for process_file_section
    short m_lastrule;

    class CSyntaxStack
    {
    public:
        void init() { m_top=0; }
        void push(short val) { m_vec[m_top++]=val; }
        short pop() {return m_vec[--m_top]; }

    private:
        short m_vec[15];    // should be plenty large enough for simple grammar
        short m_top;
    } m_stack;

    struct CSemanticStack
    {
        void init() { m_top=0; }
        void push(ddfml_symbol val) { m_vec[m_top].m_bIsStrVal=false; m_vec[m_top++].m_enumval=val; }
        void push(string& val) { m_vec[m_top].m_bIsStrVal=true; m_vec[m_top++].m_strval=val; }
        void pushemptystr() { m_vec[m_top].m_bIsStrVal=true; m_vec[m_top++].m_strval.erase(); }

        struct CSymbolValue
        {
            string m_strval;
            ddfml_symbol m_enumval;
            bool m_bIsStrVal;
        } m_vec[4];         // enough for limited language
        
        short m_top;
    } m_symbolstack;
};

#define FUNC "parse"
HRESULT CParser::parse(LPCSTR start, LPCSTR end)
{
    // This function's job is to syntactically and semantically parse the mmap file
    // region between start and end.  It assumes "<DDF" is start-4 and that
    // *end='>'.
    ddfml_tokenclass tokclass;
    short symbol=attrs;
    
    m_lastrule=-1;
    m_scanner.init(start,end);
    m_stack.init();
    m_stack.push(-1);   // stop signal
    m_symbolstack.init();

    // Get an initial token.
    if (!m_scanner.get_token(tokclass,m_tokstr))
    {
#ifndef NSAPI_OFF
        log_error(LOG_FAILURE,FUNC,m_sn,m_rq,"missing end quote: %s",m_tokstr.c_str());
#else
        fprintf(stderr,"missing end quote: %s\n",m_tokstr.c_str());
#endif
        return DDFML_E_SCANNER;
    }

    // Once we pop a -1 off the stack, we're done.
    while (symbol!=-1)
    {
        // If we've reached a terminal in the grammar, compare it to the token.
        if (istoken(symbol))
        {
            // If the terminal matches our token, push the token value on the symbol stack,
            // get the next token, and pop the syntax stack.
            if (symbol==tokclass)
            {
                if (symbol==member_name)
                    m_symbolstack.push(m_tokstr);
                else if (symbol==condop)
                {
                    if (m_tokstr=="EQ")
                        m_symbolstack.push(eq_sym);
                    else if (m_tokstr=="NE")
                        m_symbolstack.push(ne_sym);
                    else if (m_tokstr=="GT")
                        m_symbolstack.push(gt_sym);
                    else if (m_tokstr=="LT")
                        m_symbolstack.push(lt_sym);
                    else if (m_tokstr=="GE")
                        m_symbolstack.push(ge_sym);
                    else if (m_tokstr=="LE")
                        m_symbolstack.push(le_sym);
                }

                if (!m_scanner.get_token(tokclass,m_tokstr))
                {
#ifndef NSAPI_OFF
                    log_error(LOG_FAILURE,FUNC,m_sn,m_rq,"missing end quote: %s",m_tokstr.c_str());
#else
                    fprintf(stderr,"missing end quote: %s\n",m_tokstr.c_str());
#endif
                    return DDFML_E_SCANNER;
                }
                symbol=m_stack.pop();
            }
            else
            {
#ifndef NSAPI_OFF
                log_error(LOG_FAILURE,FUNC,m_sn,m_rq,"token mismatch: found %u, expected %u",
                            tokclass,symbol);
#else
                fprintf(stderr,"token mismatch: found %u, expected %u\n",tokclass,symbol);
#endif
                return DDFML_E_BADTOKEN;
            }
        }
        // The only funky rule is the empty member rule, because of the simplistic
        // stack we have.  Have to make sure we push an empty string onto the stack.
        else if (isrule(symbol))
        {
            if (symbol==member_empty_rule)
                m_symbolstack.pushemptystr();
            else if (symbol==condexp_empty_rule)
                m_symbolstack.push(null_sym);
            m_lastrule=symbol;
            symbol=m_stack.pop();
        }
        // We have a non-terminal. Use the token to choose a rule, and then
        // expand it in reverse on the stack.
        else
        {
            short rule=parse_table[symbol-NONTERM_START][tokclass];
            if (rule!=-1)
            {
                m_stack.push(rule);
                short n,i=0;
                while ((n=rules_table[rule-RULE_START][i++])!=-1)
                    m_stack.push(n);
                symbol=m_stack.pop();
            }
            else
            {
#ifndef NSAPI_OFF
                log_error(LOG_FAILURE,FUNC,m_sn,m_rq,"parsing error: nonterminal %u, token %u",
                          symbol-NONTERM_START,tokclass);
#else
                fprintf(stderr,"parsing error: nonterminal %u, token %u",
                        symbol-NONTERM_START,tokclass);
#endif
                return DDFML_E_PARSER;
            }
        }
    }
    return NOERROR;
}


// recursive subfunction that directs parser
#undef FUNC
#define FUNC "process_file_section"
HRESULT CParser::process_file_section(CDDF obj,
                                      unsigned long index,
                                      LPCSTR start,
                                      LPCSTR end,
                                      LPCSTR& block_end,
                                      unsigned long ulNestLevel,
                                      bool bEatInput)
{
    // We need to chew on the entire range (up to, but not including end).
    while (start<end)
    {
        // Look for "<DDF" sequence.
        LPCSTR mark=bufstr(start,"<DDF",end-start);

        // If nested, look for </DDF> block closing.
        block_end=NULL;
        if (ulNestLevel>0)
        {
            block_end=bufstr(start,"</DDF>",end-start);
            if (block_end==NULL)
            {
                char buf[50];
                sprintf(buf,"DDFML_E_OPENBLOCK: %%.%us\n",(end-start>20) ? 20 : end-start);
#ifndef NSAPI_OFF
                log_error(LOG_FAILURE,FUNC,m_sn,m_rq,buf,start);
#else
                fprintf(stderr,buf,start);
#endif
                return DDFML_E_OPENBLOCK;
            }

            // Now, this is ugly, but without using lex/yacc...
            if (mark==NULL || block_end<mark)
            {
                // No more DDFML markup between start and the enclosing block.
                // Echo the entire range up to block_end to sockbuf.
                if (bEatInput)
                    return NOERROR;
#ifndef NSAPI_OFF
                return (IO_OKAY==m_sb.write(start,block_end-start)) ? NOERROR : DDFML_E_NETIO;
#else
                fwrite(start,sizeof(char),block_end-start,stdout);
                return NOERROR;
#endif
            }
        }
        
        if (mark==NULL || mark+4>=end)
        {
            // We're clean.  Echo the entire buffer to sockbuf.
            if (bEatInput)
                return NOERROR;
#ifndef NSAPI_OFF
            return (IO_OKAY==m_sb.write(start,end-start)) ? NOERROR : DDFML_E_NETIO;
#else
            fwrite(start,sizeof(char),end-start,stdout);
            return NOERROR;
#endif
        }

        // Echo up to mark.
        if (!bEatInput)
        {
#ifndef NSAPI_OFF
            if (IO_ERROR==m_sb.write(start,mark-start))
                return DDFML_E_NETIO;
#else
            fwrite(start,sizeof(char),mark-start,stdout);
#endif
        }
        
        // Store offset past DDF part. If we can find a '>', we're golden.
        LPCSTR parse_start=mark+4;
        LPCSTR parse_end=(LPCSTR)memchr(parse_start,'>',end-parse_start);
        if (parse_end==NULL)
        {
            // <DDF without a > will be echoed, as a matter of convention.
            if (bEatInput)
                return NOERROR;
#ifndef NSAPI_OFF
            return (IO_OKAY==m_sb.write(mark,end-mark)) ? NOERROR : DDFML_E_NETIO;
#else
            fwrite(mark,sizeof(char),end-mark,stdout);
            return NOERROR;
#endif
        }

        // Parse the section between and advance start pointer.
        HRESULT hr=parse(parse_start,parse_end);
        if (FAILED(hr))
            return hr;
        start=parse_end+1;

        // Parsing depends on rule. Block rules result in recursive parsing
        // of region between start and end.
        bool bNot=false;
        switch (m_lastrule)
        {
            case member_rule:
            case literal_rule:
            {
                // Output value of optionally named member.
                // Name of member is on top of symbol stack.
                if (!bEatInput)
                {
                    CDDF temp((HDDF)NULL);
                    if (m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.empty())
                        temp=obj;
                    else
                        temp=obj.getmember(m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str());
#ifndef NSAPI_OFF
                    if (temp.isstr() && temp.strlength()>0)
                    {
                        // May need to check for some special characters.
                        if (m_lastrule==literal_rule || strpbrk(temp,"\"<>&")==NULL)
                        {
                            if (IO_ERROR==m_sb.write(temp,strlen(temp)))
                                return DDFML_E_NETIO;
                        }
                        else
                        {
                            for (const char* cp=temp; *cp; cp++)
                            {
                                int ret;
                                switch (*cp)
                                {
                                    case '"':   ret=m_sb.write("&quot;",6); break;
                                    case '<':   ret=m_sb.write("&lt;",4); break;
                                    case '>':   ret=m_sb.write("&gt;",4); break;
                                    case '&':   ret=m_sb.write("&amp;",5); break;
                                    default:    ret=m_sb.putc(*cp);
                                }
                                if (ret==IO_ERROR)
                                    return DDFML_E_NETIO;
                            }
                        }
                    }
                    else if (temp.isint() || temp.isstruct() ||
                             temp.islist() || temp.isbytearray())
                    {
                        char numstr[20];
                        util_snprintf(numstr,sizeof(numstr),"%ld",(long)temp);
                        if (IO_ERROR==m_sb.write(numstr,strlen(numstr)))
                            return DDFML_E_NETIO;
                    }
                    else if (temp.isfloat())
                    {
                        char numstr[25];
                        util_snprintf(numstr,sizeof(numstr),"%f",(double)temp);
                        if (IO_ERROR==m_sb.write(numstr,strlen(numstr)))
                            return DDFML_E_NETIO;
                    }
#else
                    if (temp.isstr() && temp.strlength()>0)
                    {
                        // Need to check for some special characters.
                        if (m_lastrule==literal_rule || strpbrk(temp,"\"<>&")==NULL)
                            printf("%s",(LPCSTR)temp);
                        else
                        {
                            for (const char* cp=temp; *cp; cp++)
                            {
                                int ret;
                                switch (*cp)
                                {
                                    case '"':   printf("&quot;"); break;
                                    case '<':   printf("&lt;"); break;
                                    case '>':   printf("&gt;"); break;
                                    case '&':   printf("&amp;"); break;
                                    default:    putchar(*cp);
                                }
                            }
                        }
                    }
                    else if (temp.isint() || temp.isstruct() ||
                             temp.islist() || temp.isbytearray())
                        printf("%ld",(long)temp);
                    else if (temp.isfloat())
                        printf("%f",(double)temp);
#endif
                }
                break;
            }

            case list_rule:
            {
                // Region between start and must be repeatedly processed, once
                // for each list element.
                long end_pos=-1;
                if (!m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.empty())
                    end_pos=strtoul(m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str(),NULL,10);
                long start_pos=0;
                if (!m_symbolstack.m_vec[m_symbolstack.m_top-2].m_strval.empty())
                    start_pos=strtoul(m_symbolstack.m_vec[m_symbolstack.m_top-2].m_strval.c_str(),NULL,10);

                CDDF listobj((HDDF)NULL);
                if (m_symbolstack.m_vec[m_symbolstack.m_top-3].m_strval.empty())
                    listobj=obj;
                else
                    listobj=obj.getmember(m_symbolstack.m_vec[m_symbolstack.m_top-3].m_strval.c_str());
                if (!listobj.isnull() && !listobj.islist() && !listobj.isstruct())
                {
                    char buf[50];
                    sprintf(buf,"DDFML_E_DDFNOTLIST: %%.%us\n",parse_end-parse_start);
#ifndef NSAPI_OFF
                    log_error(LOG_FAILURE,FUNC,m_sn,m_rq,buf,parse_start);
#else
                    fprintf(stderr,buf,parse_start);
#endif
                    return DDFML_E_DDFNOTLIST;
                }

                // Call ourselves recursively for each element in specified range.
                LPCSTR sub_block_end=NULL;
                unsigned long subindex=0;

                // If count is zero, process section, but eat input.
                if ((long)listobj==0 || bEatInput)
                {
                    hr=process_file_section(listobj,
                                            subindex,
                                            start,
                                            end,
                                            sub_block_end,
                                            ulNestLevel+1,
                                            true);
                    if (FAILED(hr) || hr==S_FALSE)
                        return hr;
                }
                else
                {
                    CDDF element=listobj.first();
                    while (!element.isnull())
                    {
                        hr=process_file_section(element,
                                                subindex,
                                                start,
                                                end,
                                                sub_block_end,
                                                ulNestLevel+1,
                                                (bEatInput || start_pos>subindex || (end_pos!=-1 && end_pos<subindex)));
                        if (FAILED(hr) || hr==S_FALSE)
                            return hr;
                        subindex++;
                        element=listobj.next();
                    }
                }
                start=sub_block_end+6;
                break;
            }

            case index_rule:
            {
                // INDEX rule - write index numeral to sockbuf
                if (!bEatInput)
                {
#ifndef NSAPI_OFF
                    char numstr[20];
                    sprintf(numstr,"%lu",index+1);
                    if (IO_ERROR==m_sb.write(numstr,strlen(numstr)))
                        return DDFML_E_NETIO;
#else
                    printf("%lu",index+1);
#endif
                }
                break;
            }

            case down_rule:
            {
                // Descend into DDF based on member name on top of symbol stack.
                if (!bEatInput &&
                    !m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.empty())
                    obj=obj.getmember(m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str());
                break;
            }

            case downblock_rule:
            {
                LPCSTR sub_block_end=NULL;
                HRESULT hr=process_file_section(
                    obj.getmember(m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str()),
                    index,
                    start,
                    end,
                    sub_block_end,
                    ulNestLevel+1,
                    bEatInput
                    );
                if (FAILED(hr) || hr==S_FALSE)
                    return hr;
                start=sub_block_end+6;
                break;
            }

            case up_rule:
            {
                // Ascend DDF to parent.
                if (!bEatInput)
                {
                    unsigned long upcount=1;
                    if (!m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.empty())
                        upcount=
                            strtoul(m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str(),NULL,10);
                    while (upcount--)
                        obj=obj.parent();
                }
                break;
            }

            case upblock_rule:
            {
                // Ascend DDF to parent.
                CDDF upobj=obj;
                if (!bEatInput)
                {
                    unsigned long upcount=1;
                    if (!m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.empty())
                        upcount=
                            strtoul(m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str(),NULL,10);
                    while (upcount--)
                        upobj=upobj.parent();
                }
                
                LPCSTR sub_block_end=NULL;
                HRESULT hr=process_file_section(upobj,
                                                index,
                                                start,
                                                end,
                                                sub_block_end,
                                                ulNestLevel+1,
                                                bEatInput);
                if (FAILED(hr) || hr==S_FALSE)
                    return hr;
                start=sub_block_end+6;
                break;
            }

            case ifnot_rule: bNot=true;
            case if_rule:
            {
                // Region between start and mark must be processed iff the conditional expression
                // is valid.
                bool bSubEatInput=false;
                if (!bEatInput)
                {
                    if (!m_symbolstack.m_vec[m_symbolstack.m_top-1].m_bIsStrVal &&
                        m_symbolstack.m_vec[m_symbolstack.m_top-1].m_enumval==null_sym)
                    {
                        // Top of stack is empty, so this is a straight member check, using
                        // string below top of stack.
                        if (m_symbolstack.m_vec[m_symbolstack.m_top-2].m_strval.empty() ||
                            obj.getmember(m_symbolstack.m_vec[m_symbolstack.m_top-2].m_strval.c_str()).isnull())
                            bSubEatInput=!bNot;
                        else
                            bSubEatInput=bNot;
                    }
                    else
                    {
                        // Get a reference to the member in question.
                        CDDF memobj((HDDF)NULL);
                        if (!m_symbolstack.m_vec[m_symbolstack.m_top-3].m_strval.empty())
                            memobj=obj.getmember(m_symbolstack.m_vec[m_symbolstack.m_top-3].m_strval.c_str());

                        // Get symbol value of conditional operator.
                        ddfml_symbol condop_val=m_symbolstack.m_vec[m_symbolstack.m_top-2].m_enumval;
                        
                        // Operation depends on type of submember.
                        if (memobj.isnull() || memobj.isempty()  || memobj.isbytearray())
                        {
                            // For these types, only an EQ comparison to non-null will be invalid.
                            if (condop_val==eq_sym &&
                                !m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.empty())
                                bSubEatInput=!bNot;
                            else
                                bSubEatInput=bNot;
                        }
                        else if (memobj.isstr())
                        {
                            // Check if second operand is a member.
                            LPCSTR ts=NULL;
                            char tbuf[255];
                            CDDF mem2obj=obj.getmember(m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str());
                            if (mem2obj.isnull())
                                ts=m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str();
                            else if (mem2obj.isstr())
                                ts=mem2obj;
                            else if (mem2obj.isint())
                                ts=mem2obj.strfromint(tbuf);
                            else if (mem2obj.isfloat())
                                ts=mem2obj.strfromfloat(tbuf);
                            int result=strcmp(((LPCSTR)memobj)==NULL ? "" : (LPCSTR)memobj,
                                              (ts ? ts : ""));
                            if ((condop_val==eq_sym && result!=0) ||
                                (condop_val==ne_sym && result==0) ||
                                (condop_val==gt_sym && result<=0) ||
                                (condop_val==lt_sym && result>=0) ||
                                (condop_val==ge_sym && result<0) ||
                                (condop_val==le_sym && result>0))
                                bSubEatInput=!bNot;
                            else
                                bSubEatInput=bNot;
                        }
                        else if (memobj.isfloat())
                        {
                            // Check if second operand is a member.
                            double op2=0;
                            CDDF mem2obj=
                                obj.getmember(m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str());
                            if (mem2obj.isfloat())
                                op2=(double)mem2obj;
                            else
                            {
                                LPCSTR ts=m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str();
                                op2=atof(ts ? ts : "");
                            }

                            // Do a floating point comparison.
                            double op1=(double)memobj;
                            if ((condop_val==eq_sym && op1!=op2) ||
                                (condop_val==ne_sym && op1==op2) ||
                                (condop_val==gt_sym && op1<=op2) ||
                                (condop_val==lt_sym && op1>=op2) ||
                                (condop_val==ge_sym && op1<op2) ||
                                (condop_val==le_sym && op1>op2))
                                bSubEatInput=!bNot;
                            else
                                bSubEatInput=bNot;
                        }
                        else
                        {
                            // Check if second operand is a member.
                            long op2=0;
                            CDDF mem2obj=
                                obj.getmember(m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str());
                            if (!mem2obj.isnull())
                                op2=(long)mem2obj;
                            else
                            {
                                LPCSTR ts=m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str();
                                op2=atol(ts ? ts : "");
                            }

                            // Do an integer comparison.
                            long op1=(long)memobj;
                            if ((condop_val==eq_sym && op1!=op2) ||
                                (condop_val==ne_sym && op1==op2) ||
                                (condop_val==gt_sym && op1<=op2) ||
                                (condop_val==lt_sym && op1>=op2) ||
                                (condop_val==ge_sym && op1<op2) ||
                                (condop_val==le_sym && op1>op2))
                                bSubEatInput=!bNot;
                            else
                                bSubEatInput=bNot;
                        }
                    }
                }
                
                LPCSTR sub_block_end=NULL;
                hr=process_file_section(obj,
                                        index,
                                        start,
                                        end,
                                        sub_block_end,
                                        ulNestLevel+1,
                                        bEatInput || bSubEatInput);
                if (FAILED(hr) || hr==S_FALSE)
                    return hr;
                start=sub_block_end+6;
                break;
            }

            case time_rule:
            {
                // Output current date/time via strftime function.
                if (!bEatInput)
                {
                    time_t t=time(NULL);
                    struct tm* ts=localtime(&t);
                    char timebuf[256]="";
                    strftime(timebuf,
                             255,
                             m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str(),
                             ts);
#ifndef NSAPI_OFF
                    if (IO_ERROR==m_sb.write(timebuf,strlen(timebuf)))
                        return DDFML_E_NETIO;
#else
                    printf("%s",timebuf);
#endif
                }
                break;
            }

            case abort_rule:
            {
                // If not eating input, execute an abort.
                if (!bEatInput)
                    return S_FALSE;
                break;
            }

            case file_rule:
            {
                if (!bEatInput)
                {
                    // Flush socket, and then parse specified template.
#ifndef NSAPI_OFF
                    m_sb.flush();
#endif
                    hr=ddfml_parse(obj,m_symbolstack.m_vec[m_symbolstack.m_top-1].m_strval.c_str(),
#ifndef NSAPI_OFF
                                   m_sn,m_rq
#endif
                               );
                    if (FAILED(hr) || hr==S_FALSE)
                        return hr;
                }
                break;
            }
        }
    }
    return NOERROR;
}

// master function that maps file into memory and starts process
#undef FUNC
#define FUNC "ddfml_parse"
DDFSVC_EXPORT HRESULT __stdcall ddfml_parse(CDDF obj, LPCSTR pathname
#ifndef NSAPI_OFF
                                            ,Session* sn, Request* rq
#endif
                                    )
{
    // Construct a path name.
#ifdef WIN32
    char pathbuf[MAX_PATH+1];
#else
    char pathbuf[PATH_MAX+1];
#endif
    if (*pathname!=PATH_SEP && !g_DDFMLTemplateRoot.empty())
    {
        strcpy(pathbuf,g_DDFMLTemplateRoot.c_str());
        strcat(pathbuf,PATH_SEP_STRING);
        strcat(pathbuf,pathname);
    }
    else
        strcpy(pathbuf,pathname);


    // Open and map file into memory. Need file size for end boundary.
#ifdef WIN32
    HANDLE hFile=CreateFile(
        pathbuf,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,   // default security
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
        );
    if (hFile==INVALID_HANDLE_VALUE)
#else
    int hFile=open(pathbuf,O_RDONLY);
    if (hFile<0)
#endif
    {
#ifndef NSAPI_OFF
        log_error(LOG_FAILURE,FUNC,sn,rq,"open: %s\n",pathbuf);
#else
        fprintf(stderr,"internal error: open: %s\n",pathbuf);
#endif
        return DDFML_E_FILEIO;
    }

#ifdef WIN32
    DWORD fsize=GetFileSize(hFile,NULL);
    if (fsize==INVALID_FILE_SIZE)
    {
        CloseHandle(hFile);
#else
    off_t fsize;
    struct stat statbuf;
    if (fstat(hFile,&statbuf)==0)
        fsize=statbuf.st_size;
    else
    {
        close(hFile);
#endif
#ifndef NSAPI_OFF
        log_error(LOG_FAILURE,FUNC,sn,rq,"fstat: %s\n",pathbuf);
#else
        fprintf(stderr,"internal error: fstat: %s\n",pathbuf);
#endif
        return DDFML_E_FILEIO;
    }

#ifdef WIN32
    HANDLE hMapping=CreateFileMapping(
        hFile,
        NULL,   // default security
        PAGE_READONLY,
        0,0,
        NULL    // no name for now - change later for optimization
        );
    if (hMapping==NULL)
    {
        CloseHandle(hFile);
#ifndef NSAPI_OFF
        log_error(LOG_FAILURE,FUNC,sn,rq,"CreateFileMapping: %s\n",pathbuf);
#else
        fprintf(stderr,"internal error: CreateFileMapping: %s\n",pathbuf);
#endif
        return DDFML_E_FILEIO;
    }

    LPCSTR start=(LPCSTR)MapViewOfFile(
        hMapping,
        FILE_MAP_READ,
        0,0,0
        );
    if (start==NULL)
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
#ifndef NSAPI_OFF
        log_error(LOG_FAILURE,FUNC,sn,rq,"MapViewOfFile: %s\n",pathbuf);
#else
        fprintf(stderr,"internal error: MapViewOfFile: %s\n",pathbuf);
#endif
        return DDFML_E_FILEIO;
    }
#else
    LPCSTR start=(LPCSTR)mmap(
        0,      // put it anywhere
        fsize,  // size of file
        PROT_READ,
        MAP_SHARED,
        hFile,
        0       // offset
        );
    if (start==MAP_FAILED)
    {
        close(hFile);
#ifndef NSAPI_OFF
        log_error(LOG_FAILURE,FUNC,sn,rq,"mmap: %s\n",pathbuf);
#else
        fprintf(stderr,"internal error: mmap: %s\n",pathbuf);
#endif
        return DDFML_E_FILEIO;
    }
#endif
    
    // Parse the file.
    HRESULT hr;
#ifndef NSAPI_OFF
    CParser p(sn,rq);
#else
    CParser p;
#endif
    LPCSTR dummy_block_start=NULL;
    try
    {
        hr=p.process_file_section(obj,0,start,start+fsize,dummy_block_start);
    }
    catch(bad_alloc)
    {
#ifndef NSAPI_OFF
        log_error(LOG_FAILURE,FUNC,sn,rq,"out of memory");
#else
        fprintf(stderr,"out of memory");
#endif
        hr=E_OUTOFMEMORY;
    }

#ifdef WIN32
    UnmapViewOfFile(start);
    CloseHandle(hMapping);
    CloseHandle(hFile);
#else
    munmap((char*)start,fsize);
    close(hFile);
#endif
    p.flush();
    return hr;
}

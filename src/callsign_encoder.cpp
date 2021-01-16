//==========================================================================
// Name:            callsign_decoder.cpp
//
// Purpose:         Encodes and decodes received callsigns.
// Created:         December 26, 2020
// Authors:         Mooneer Salem
//
// License:
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License version 2.1,
//  as published by the Free Software Foundation.  This program is
//  distributed in the hope that it will be useful, but WITHOUT ANY
//  WARRANTY; without even the implied warranty of MERCHANTABILITY or
//  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
//  License for more details.
//
//  You should have received a copy of the GNU Lesser General Public License
//  along with this program; if not, see <http://www.gnu.org/licenses/>.
//
//==========================================================================

#include <cstdlib>
#include <cstring>
#include "callsign_encoder.h"

CallsignEncoder::CallsignEncoder()
{
    memset(&translatedCallsign_, 0, MAX_CALLSIGN);
    memset(&truncCallsign_, 0, MAX_CALLSIGN);
    memset(&callsign_, 0, MAX_CALLSIGN/2);
    clearReceivedText();
    
    // Initialize Hadamard codewords. Since we're only encoding three bits,
    // we can just hardcode them here and brute force our way through the 
    // decode.
    hadamardCodewords_[0] = 0b00000000;
    hadamardCodewords_[1] = 0b00001111;
    hadamardCodewords_[2] = 0b00110011;
    hadamardCodewords_[3] = 0b00111100;
    hadamardCodewords_[4] = 0b01010101;
    hadamardCodewords_[5] = 0b01011010;
    hadamardCodewords_[6] = 0b01100110;
    hadamardCodewords_[7] = 0b01101001;
    
    srand (time(NULL));
}

CallsignEncoder::~CallsignEncoder()
{
    // empty
}

void CallsignEncoder::setCallsign(const char* callsign)
{
    memset(&translatedCallsign_, 0, MAX_CALLSIGN);
    memset(&truncCallsign_, 0, MAX_CALLSIGN);
    memset(&callsign_, 0, MAX_CALLSIGN/2);
    
    memcpy(&callsign_, callsign, strlen(callsign) + 1);
    convert_callsign_to_ota_string_(callsign_, &translatedCallsign_[4]);
    
    unsigned char crc = calculateCRC8_((char*)&translatedCallsign_[4], strlen(&translatedCallsign_[4]));
    translatedCallsign_[0] = 39;
    translatedCallsign_[1] = 39;
    unsigned char crcDigit1 = crc >> 4;
    unsigned char crcDigit2 = crc & 0xF;
    convertDigitToASCII_(&translatedCallsign_[2], crcDigit1);
    convertDigitToASCII_(&translatedCallsign_[3], crcDigit2);
    
    int truncIndex = 0;
    for(int index = 0; index < strlen(translatedCallsign_); index += 2, truncIndex += 4)
    {
        // Encode two characters as four bytes and interleave them together.
        hadamardEncodeSymbol_(translatedCallsign_[index], &truncCallsign_[truncIndex]);
        hadamardEncodeSymbol_(translatedCallsign_[index + 1], &truncCallsign_[truncIndex + 2]);
        //fprintf(stderr, "tx: 0 = %x, 1 = %x, 2 = %x, 3 = %x\n", truncCallsign_[truncIndex], truncCallsign_[truncIndex+1], truncCallsign_[truncIndex+2], truncCallsign_[truncIndex+3]);
        interleave_(&truncCallsign_[truncIndex]);
        /*fprintf(stderr, "tx: 0 = %x, 1 = %x, 2 = %x, 3 = %x\n", truncCallsign_[truncIndex], truncCallsign_[truncIndex+1], truncCallsign_[truncIndex+2], truncCallsign_[truncIndex+3]);
        deinterleave_(&truncCallsign_[truncIndex]);
        fprintf(stderr, "tx: 0 = %x, 1 = %x, 2 = %x, 3 = %x\n", truncCallsign_[truncIndex], truncCallsign_[truncIndex+1], truncCallsign_[truncIndex+2], truncCallsign_[truncIndex+3]);
        fprintf(stderr, "======\n");
        interleave_(&truncCallsign_[truncIndex]);*/
    }
}

void CallsignEncoder::clearReceivedText()
{
    memset(&receivedCallsign_, 0, MAX_CALLSIGN);
    pReceivedCallsign_ = &receivedCallsign_[0];
    textInSync_ = false;
    pendingGolayBytes_.clear();
}

void CallsignEncoder::pushReceivedByte(char incomingChar)
{
    // If we're not in sync, we should look for a space to establish sync.
    pendingGolayBytes_.push_back(incomingChar);
    if (!textInSync_)
    {
        if (pendingGolayBytes_.size() >= 4)
        {
            // Minimum number of characters received to begin attempting sync.
            // Strip out MSB of each byte as it's not used for encoding.
            char temp[4];
            temp[0] = pendingGolayBytes_[pendingGolayBytes_.size() - 4] & 0x7F;
            temp[1] = pendingGolayBytes_[pendingGolayBytes_.size() - 3] & 0x7F;
            temp[2] = pendingGolayBytes_[pendingGolayBytes_.size() - 2] & 0x7F;
            temp[3] = pendingGolayBytes_[pendingGolayBytes_.size() - 1] & 0x7F;
            deinterleave_(temp);

            //fprintf(stderr, "rx: 0 = %x, 1 = %x, 2 = %x, 3 = %x\n", temp[0], temp[1], temp[2], temp[3]);
            char rawStr[3];
            char decodedStr[3];
            
            hadamardDecodeSymbol_(&temp[0], &rawStr[0], false);
            hadamardDecodeSymbol_(&temp[2], &rawStr[1], false);
            rawStr[2] = 0;
            
            if (rawStr[0] == 0 || rawStr[1] == 0) return;
            
            fprintf(stderr, "rx: 0 = %x, 1 = %x\n", rawStr[0], rawStr[1]);
            
            convert_ota_string_to_callsign_(rawStr, decodedStr);
            if (decodedStr[0] == 0x7F && decodedStr[1] == 0x7F)
            {
                // We're now in sync. Pop off the non-aligned bytes we received at the beginning
                // (if any) and give us the chance to decode the remaining ones.
                textInSync_ = true;
                fprintf(stderr, "text now in sync\n");
                pendingGolayBytes_.clear();
            }
        }
    }
    else
    {
        while (pendingGolayBytes_.size() >= 4)
        {
            // Minimum number of characters received.
            // Strip out MSB of each byte as it's not used for encoding.
            char temp[4];
            temp[0] = pendingGolayBytes_[0] & 0x7F;
            temp[1] = pendingGolayBytes_[1] & 0x7F;
            temp[2] = pendingGolayBytes_[2] & 0x7F;
            temp[3] = pendingGolayBytes_[3] & 0x7F;
            pendingGolayBytes_.pop_front();
            pendingGolayBytes_.pop_front();
            pendingGolayBytes_.pop_front();
            pendingGolayBytes_.pop_front();
            deinterleave_(temp);
            char rawStr[3];
            char decodedStr[3];
            
            hadamardDecodeSymbol_(&temp[0], &rawStr[0], true);
            hadamardDecodeSymbol_(&temp[2], &rawStr[1], true);
            rawStr[2] = 0;
            
            if (rawStr[0] == 0 || rawStr[1] == 0)
            {
                fprintf(stderr, "lost sync\n");
                textInSync_ = false;
                break;
            }
            
            fprintf(stderr, "rx: 1=%x, 2=%x\n", rawStr[0], rawStr[1]);
            convert_ota_string_to_callsign_(rawStr, decodedStr);

            if ((decodedStr[0] == '\r' || decodedStr[0] == 0x7F || decodedStr[0] == 0) || ((pReceivedCallsign_ - &receivedCallsign_[0]) > MAX_CALLSIGN-1))
            {                        
                // CR or sync completes line
                if (pReceivedCallsign_ != &receivedCallsign_[0])
                {
                    *pReceivedCallsign_ = 0;
                    pReceivedCallsign_ = &receivedCallsign_[0];
                }
            }
            else
            {
                // Ignore incoming nulls but wipe anything to the right of the current pointer
                // if we're overwriting one.
                if (*pReceivedCallsign_ == 0)
                {
                    memset(pReceivedCallsign_, 0, MAX_CALLSIGN - (pReceivedCallsign_ - &receivedCallsign_[0]));
                }
                *pReceivedCallsign_++ = decodedStr[0];
            }
            
            if ((decodedStr[1] == '\r' || decodedStr[1] == 0x7F || decodedStr[1] == 0) || ((pReceivedCallsign_ - &receivedCallsign_[0]) > MAX_CALLSIGN-1))
            {
                // CR/sync completes line
                if (pReceivedCallsign_ != &receivedCallsign_[0])
                {
                    *pReceivedCallsign_ = 0;
                    pReceivedCallsign_ = &receivedCallsign_[0];
                }
            }
            else
            {
                // Ignore incoming nulls but wipe anything to the right of the current pointer
                // if we're overwriting one.
                if (*pReceivedCallsign_ == 0)
                {
                    memset(pReceivedCallsign_, 0, MAX_CALLSIGN - (pReceivedCallsign_ - &receivedCallsign_[0]));
                }
                *pReceivedCallsign_++ = decodedStr[1];
            }
        }
    }
}

bool CallsignEncoder::isCallsignValid() const
{
    if (strlen(receivedCallsign_) <= 2)
    {
        return false;
    }
    
    // Retrieve received CRC and calculate the CRC from the other received text.
    unsigned char receivedCRC = convertHexStringToDigit_((char*)&receivedCallsign_[0]);
    
    char buf[MAX_CALLSIGN];
    memset(&buf, 0, MAX_CALLSIGN);
    convert_callsign_to_ota_string_(&receivedCallsign_[2], &buf[0]);
    unsigned char calcCRC = calculateCRC8_((char*)&buf, strlen(&buf[0]));
    
    // Return true if both are equal.
    return receivedCRC == calcCRC;
}

// 6 bit character set for text field use:
// 0: ASCII null
// 1-26: ASCII 'A'-'Z'
// 27-36: ASCII '0'-'9'
// 37: ASCII '/'
// 38: TBD/for future use.
// 39: sync
void CallsignEncoder::convert_callsign_to_ota_string_(const char* input, char* output) const
{
    int outidx = 0;
    
    for (int index = 0; index < strlen(input); index++)
    {
        if (input[index] >= 'A' && input[index] <= 'Z')
        {
            output[outidx++] = input[index] - 'A' + 1;
        }
        else if (input[index] >= '0' && input[index] <= '9')
        {
            output[outidx++] = (input[index] - '0') + 27;
        }
        else if (input[index] == '/')
        {
            output[outidx++] = 37;
        }
        else
        {
            // Invalid characters are sync characters.
            output[outidx++] = 39;
        }
    }
    
    // We also add up to three sync characters (63) to the end depending
    // on the current length.
    if (outidx % 2)
    {
        output[outidx++] = 39;
    }
    output[outidx++] = 39;
    output[outidx++] = 39;
    output[outidx] = 0;
}

void CallsignEncoder::convert_ota_string_to_callsign_(const char* input, char* output)
{
    int outidx = 0;
    for (int index = 0; index < strlen(input); index++)
    {
        if (input[index] >= 1 && input[index] <= 26)
        {
            output[outidx++] = (input[index] - 1) + 'A';
         }
        else if (input[index] >= 27 && input[index] <= 36)
         {
            output[outidx++] = (input[index] - 27) + '0';
         }
        else if (input[index] == 37)
         {
            output[outidx++] = '/';
         }
        // 38 is TBD
        else if (input[index] == 39)
         {
            // Use ASCII 0x7F to signify sync. The caller will need to strip this out.
            output[outidx++] = 0x7F;
        }
        else
        {
            // Invalid characters become spaces. 
            output[outidx++] = ' ';
        }
    }
    output[outidx] = 0;
}

unsigned char CallsignEncoder::calculateCRC8_(char* input, int length) const
{
    unsigned char generator = 0x1D;
    unsigned char crc = 0; /* start with 0 so first byte can be 'xored' in */

    while (length > 0)
    {
        unsigned char ch = *input++;
        length--;

        // Ignore 6-bit carriage return and sync characters.
        if (ch == 39) continue;
        
        crc ^= ch; /* XOR-in the next input byte */
        
        for (int i = 0; i < 8; i++)
        {
            if ((crc & 0x80) != 0)
            {
                crc = (unsigned char)((crc << 1) ^ generator);
            }
            else
            {
                crc <<= 1;
            }
        }
    }

    return crc;
}

void CallsignEncoder::convertDigitToASCII_(char* dest, unsigned char digit)
{
    if (digit >= 0 && digit <= 9)
    {
        *dest = digit + 27; // using 6 bit character set defined above.
    }
    else if (digit >= 0xA && digit <= 0xF)
    {
        *dest = (digit - 0xA); // using 6 bit character set defined above.
    }
    else
    {
        // Should not reach here.
        *dest = 10;
    }
}

unsigned char CallsignEncoder::convertHexStringToDigit_(char* src) const
{
    unsigned char ret = 0;
    for (int i = 0; i < 2; i++)
    {
        ret <<= 4;
        unsigned char temp = 0;
        if (*src >= '0' && *src <= '9')
        {
            temp = *src - '0';
        }
        else if (*src >= 'A' && *src <= 'F')
        {
            temp = *src - 'A' + 0xA;
        }
        ret |= temp;
        src++;
    }
    
    return ret;
}

// Note: symbol1 and symbol2 must be <= 0x7F, which is possible since the
// current Hadamard encoding always uses MSB = 0.
int CallsignEncoder::hammingDistance_(char symbol1, char symbol2)
{
    //fprintf(stderr, "dist(%x,%x) = ", symbol1, symbol2);
    int result = 0;
    while (symbol1 > 0 || symbol2 > 0)
    {
        result += (symbol1 & 1) ^ (symbol2 & 1);
        symbol1 >>= 1;
        symbol2 >>= 1;
    }
    //fprintf(stderr, "%d\n", result);
    return result;
}

void CallsignEncoder::hadamardEncodeSymbol_(const char input, char* output)
{
    int msb = (input >> 3) & 0b111;
    int lsb = input & 0b111;
    
    output[0] = hadamardCodewords_[msb];
    output[1] = hadamardCodewords_[lsb];
}

struct HadamardDecodeOption
{
    char decodedBits;
    int distance;
};

void CallsignEncoder::hadamardDecodeSymbol_(const char* input, char* output, bool inSync)
{
    // 6 bit character encodes as 2 bytes.
    // Due to only using 39 characters in our character set, the MSB
    // can only be 000, 001, 010, 011 or 100 once decoded. Thus, we restrict our
    // sample sapce accordingly.
    std::vector<HadamardDecodeOption> decodes[2];
    
    // Generate all decode possibilities.
    int decodedWord = 0;
    for (int index = 0; index < 2; index++)
    {
        int maxWord = (index == 0 && inSync) ? 0b100 : 0b111;
        char inp = input[index];
        int minDistance = 3;
        int minWord = 0;
        for (int codeword = 0; codeword <= maxWord; codeword++)
        {
            int dist = hammingDistance_(hadamardCodewords_[codeword], inp);
            HadamardDecodeOption decode;
            decode.decodedBits = codeword;
            decode.distance = dist;
            decodes[index].push_back(decode);
            
            if (dist < minDistance)
            {
                minDistance = dist;
            }
        }
        
        // Eliminate all but the minimum distance options.
        auto iter = decodes[index].begin();
        while (iter != decodes[index].end())
        {
            if (iter->distance != minDistance)
            {
                iter = decodes[index].erase(iter);
            }
            else
            {
                iter++;
            }
        }
    }
    
    // Generate list of characters from the two lists of bits. These are the choices
    // we have to choose from.
    std::vector<char> choices;
    for (int leftIndex = 0; leftIndex < decodes[0].size(); leftIndex++)
    {
        for (int rightIndex = 0; rightIndex < decodes[1].size(); rightIndex++)
        {
            choices.push_back((decodes[0][leftIndex].decodedBits << 3) | (decodes[1][rightIndex].decodedBits));
        }
    }
    
    //fprintf(stderr, "Number of possible decode choices before pruning: %d\n", choices.size());
    
    // Prune obviously bad choices, but only if we're already in sync. Otherwise, we could inadvertently 
    // decide that the character is a sync character or similar.
    if (inSync)
    {
        auto iter = choices.begin();
        while (iter != choices.end())
        {
            if (*iter == 0 || *iter >= 40)
            {
                iter = choices.erase(iter);
            }
            else
            {
                iter++;
            }
        }
    }
    
    // If we only have a single option on both sides of the character, that's likely our character.
    // Otherwise, we might need to resync.
    if (choices.size() == 1);
    {
        decodedWord = choices[0];
    }

    output[0] = decodedWord;
}

#define GET_BIT(ch, bit) (((ch & (1 << bit)) >> bit) & 1)
#define PLACE_BIT(ch, bitFrom, bitTo) (GET_BIT(ch, bitFrom) << bitTo)

void CallsignEncoder::interleave_(char* input)
{
    char byte1 = 
        PLACE_BIT(input[0], 6, 6) |
        PLACE_BIT(input[1], 6, 5) |
        PLACE_BIT(input[2], 6, 4) |
        PLACE_BIT(input[3], 6, 3) |
        PLACE_BIT(input[0], 5, 2) |
        PLACE_BIT(input[1], 5, 1) |
        PLACE_BIT(input[2], 5, 0);
    
    char byte2 = 
        PLACE_BIT(input[3], 5, 6) |
        PLACE_BIT(input[0], 4, 5) |
        PLACE_BIT(input[1], 4, 4) |
        PLACE_BIT(input[2], 4, 3) |
        PLACE_BIT(input[3], 4, 2) |
        PLACE_BIT(input[0], 3, 1) |
        PLACE_BIT(input[1], 3, 0);
    
    char byte3 = 
        PLACE_BIT(input[2], 3, 6) |
        PLACE_BIT(input[3], 3, 5) |
        PLACE_BIT(input[0], 2, 4) |
        PLACE_BIT(input[1], 2, 3) |
        PLACE_BIT(input[2], 2, 2) |
        PLACE_BIT(input[3], 2, 1) |
        PLACE_BIT(input[0], 1, 0);
    
    char byte4 = 
        PLACE_BIT(input[1], 1, 6) |
        PLACE_BIT(input[2], 1, 5) |
        PLACE_BIT(input[3], 1, 4) |
        PLACE_BIT(input[0], 0, 3) |
        PLACE_BIT(input[1], 0, 2) |
        PLACE_BIT(input[2], 0, 1) |
        PLACE_BIT(input[3], 0, 0);
    
    input[0] = byte1;
    input[1] = byte2;
    input[2] = byte3;
    input[3] = byte4;
}

void CallsignEncoder::deinterleave_(char* input)
{
    char byte1 = 
        PLACE_BIT(input[0], 6, 6) |
        PLACE_BIT(input[0], 2, 5) |
        PLACE_BIT(input[1], 5, 4) |
        PLACE_BIT(input[1], 1, 3) |
        PLACE_BIT(input[2], 4, 2) |
        PLACE_BIT(input[2], 0, 1) |
        PLACE_BIT(input[3], 3, 0);
    
    char byte2 = 
        PLACE_BIT(input[0], 5, 6) |
        PLACE_BIT(input[0], 1, 5) |
        PLACE_BIT(input[1], 4, 4) |
        PLACE_BIT(input[1], 0, 3) |
        PLACE_BIT(input[2], 3, 2) |
        PLACE_BIT(input[3], 6, 1) |
        PLACE_BIT(input[3], 2, 0);
    
    char byte3 = 
        PLACE_BIT(input[0], 4, 6) |
        PLACE_BIT(input[0], 0, 5) |
        PLACE_BIT(input[1], 3, 4) |
        PLACE_BIT(input[2], 6, 3) |
        PLACE_BIT(input[2], 2, 2) |
        PLACE_BIT(input[3], 5, 1) |
        PLACE_BIT(input[3], 1, 0);
    
    char byte4 = 
        PLACE_BIT(input[0], 3, 6) |
        PLACE_BIT(input[1], 6, 5) |
        PLACE_BIT(input[1], 2, 4) |
        PLACE_BIT(input[2], 5, 3) |
        PLACE_BIT(input[2], 1, 2) |
        PLACE_BIT(input[3], 4, 1) |
        PLACE_BIT(input[3], 0, 0);
    
    input[0] = byte1;
    input[1] = byte2;
    input[2] = byte3;
    input[3] = byte4;
}

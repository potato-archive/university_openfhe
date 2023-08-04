
#define PROFILE

#include "openfhe.h"
//iw
#include <list>
#include <iostream>
#include <vector>
#include <cstdio>
#include <sstream>
#include <string>
//

std::vector<std::vector<double>> orig_list;
std::vector<std::string> name;
std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> crypt_list;

using namespace lbcrypto;

void AutomaticRescaleDemo(ScalingTechnique scalTech);
void ManualRescaleDemo(ScalingTechnique scalTech);
void HybridKeySwitchingDemo1();
void showdetail();
void vecprint();
void strprint();
//void errprint();


int main(int argc, char* argv[]) {
   
    AutomaticRescaleDemo(FLEXIBLEAUTO);

    // A new example that was added in OpenFHE v1.10
    //AutomaticRescaleDemo(FIXEDAUTO);

    ManualRescaleDemo(FIXEDMANUAL);

   // HybridKeySwitchingDemo1();

    return 0;
}

void AutomaticRescaleDemo(ScalingTechnique scalTech) {

    //iw
    //std::vector<std::vector<double>> orig_list;
    //std::vector<std::string> name;
    //std::list<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> crypt_list;
    //



    if (scalTech == FLEXIBLEAUTO) {
        std::cout << std::endl << std::endl << std::endl << " ===== FlexibleAutoDemo ============= " << std::endl;
    }
    else {
        std::cout << std::endl << std::endl << std::endl << " ===== FixedAutoDemo ============= " << std::endl;
    }

    uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(5);
    parameters.SetScalingModSize(50);
    parameters.SetScalingTechnique(scalTech);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Input
    std::vector<double> x = {1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07};
    Plaintext ptxt        = cc->MakeCKKSPackedPlaintext(x);

    std::cout << "Input x : " << ptxt << std::endl;

    auto c = cc->Encrypt(ptxt, keys.publicKey);

    //iw
    orig_list.push_back(x);
    name.push_back("c");
    crypt_list.push_back(c);
    vecprint();
    strprint();


    /* Computing f(x) = x^18 + x^9 + 1
   *
   * In the following we compute f(x) with a computation
   * that has a multiplicative depth of 5.
   *
   * The result is correct, even though there is no call to
   * the Rescale() operation.
   */
    //

    auto c2   = cc->EvalMult(c, c);                      // x^2


    //iw
    std::vector<double> true_result;
    std::cout << "auto c2 = cc->EvalMult(c, c)-> Expected result" << std::endl;
    for (size_t i = 0; i < orig_list[0].size(); i++)
    {
        double x = orig_list[0][i];
        true_result.push_back(x*x);
    }
    orig_list.push_back(true_result);
    crypt_list.push_back(c2);
    name.push_back("c2");
    vecprint();
    strprint();
    //errprint(keys.secretKey, cc);
    //



    auto c4   = cc->EvalMult(c2, c2);                    // x^4

    //iw
    std::vector<double> true_result1; //선언 새로 하줘서 넣어주려고 or vector를 비우는 코드를 적던가
    std::cout << "auto c4   = cc->EvalMult(c2, c2)-> Expected result" << std::endl;
    for (size_t i = 0; i < orig_list[0].size(); i++) // original에서 계속 가져와서 계산하니까 [0]으로 고정.
    {
        double x = orig_list[0][i];
        true_result1.push_back(x*x*x*x); //이거 change
    }
    orig_list.push_back(true_result1); //이것도 바뀌고
    crypt_list.push_back(c4);
    name.push_back("c4");
    vecprint();
    strprint();
    //


    auto c3   = cc->EvalMult(c2, c);                    //x^3

    //iw
    std::vector<double> true_result2; //선언 새로 하줘서 넣어주려고 or vector를 비우는 코드를 적던가
    std::cout << " auto c3   = cc->EvalMult(c2, c)-> Expected result" << std::endl;
    for (size_t i = 0; i < orig_list[0].size(); i++) // original에서 계속 가져와서 계산하니까 [0]으로 고정.
    {
        double x = orig_list[0][i];
        true_result2.push_back(x*x*x); //이거 change
    }
    orig_list.push_back(true_result2); //이것도 바뀌고
    crypt_list.push_back(c3);
    name.push_back("c3");
    vecprint();
    strprint();
    //
    
    auto c1   = cc->EvalMult(c, 4.0);              //4*x

        //iw
    std::vector<double> true_result3; //선언 새로 하줘서 넣어주려고 or vector를 비우는 코드를 적던가
    std::cout << "auto c1   = cc->EvalMult(c, 4.0)-> Expected result" << std::endl;
    for (size_t i = 0; i < orig_list[0].size(); i++) // original에서 계속 가져와서 계산하니까 [0]으로 고정.
    {
        double x = orig_list[0][i];
        true_result3.push_back(4*x); //이거 change
    }
    orig_list.push_back(true_result3); //이것도 바뀌고
    crypt_list.push_back(c1); //change
    name.push_back("c1"); //change
    vecprint();
    strprint();
    //


    auto c2_1  = cc->EvalMult(c2, 3.0); /// 3*x^2

    //iw
    std::vector<double> true_result4; //선언 새로 하줘서 넣어주려고 or vector를 비우는 코드를 적던가
    std::cout << "auto c2_1  = cc->EvalMult(c2, 3.0)-> Expected result" << std::endl;
    for (size_t i = 0; i < orig_list[0].size(); i++) // original에서 계속 가져와서 계산하니까 [0]으로 고정.
    {
        double x = orig_list[0][i];
        true_result4.push_back(3*x*x); //이거 change
    }
    orig_list.push_back(true_result4); //이것도 바뀌고
    crypt_list.push_back(c2_1); //change
    name.push_back("c2_1"); //change
    vecprint();
    strprint();
    //


    auto c3_1  = cc->EvalMult(c3, 2.0); ////2*x^3

    //iw
    std::vector<double> true_result5; //선언 새로 하줘서 넣어주려고 or vector를 비우는 코드를 적던가
    std::cout << "auto c3_1  = cc->EvalMult(c3, 2.0)-> Expected result" << std::endl;
    for (size_t i = 0; i < orig_list[0].size(); i++) // original에서 계속 가져와서 계산하니까 [0]으로 고정.
    {
        double x = orig_list[0][i];
        true_result5.push_back(2*x*x*x); //이거 change
    }
    orig_list.push_back(true_result5); //이것도 바뀌고
    crypt_list.push_back(c3_1); //change
    name.push_back("c3_1"); //change
    vecprint();
    strprint();
    //

    auto c34 = cc->EvalAdd(c4, c3);

    //iw
    std::vector<double> true_result6; //선언 새로 하줘서 넣어주려고 or vector를 비우는 코드를 적던가
    std::cout << "auto c34 = cc->EvalAdd(c4, c3)-> Expected result" << std::endl;
    for (size_t i = 0; i < orig_list[0].size(); i++) // original에서 계속 가져와서 계산하니까 [0]으로 고정.
    {
        double x = orig_list[0][i];
        true_result6.push_back(x*x*x*x+x*x*x); //이거 change
    }
    orig_list.push_back(true_result6); //이것도 바뀌고
    crypt_list.push_back(c34); //change
    name.push_back("c34"); //change
    vecprint();
    strprint();
    //


    auto c12 = cc->EvalAdd(c2_1, c1);

    //iw
    std::vector<double> true_result7; //선언 새로 하줘서 넣어주려고 or vector를 비우는 코드를 적던가
    std::cout << "auto c12 = cc->EvalAdd(c2_1, c1)-> Expected result" << std::endl;
    for (size_t i = 0; i < orig_list[0].size(); i++) // original에서 계속 가져와서 계산하니까 [0]으로 고정.
    {
        double x = orig_list[0][i];
        true_result7.push_back(3*x*x+4*x); //이거 change
    }
    orig_list.push_back(true_result7); //이것도 바뀌고
    crypt_list.push_back(c12); //change
    name.push_back("c12"); //change
    vecprint();
    strprint();
    //


    auto cRes = cc->EvalAdd(cc->EvalAdd(c34, c12), 2.0);  // Final result****


    //iw
    std::vector<double> true_result8; //선언 새로 하줘서 넣어주려고 or vector를 비우는 코드를 적던가
    std::cout << "auto cRes = cc->EvalAdd(cc->EvalAdd(c34, c12), 2.0)-> Expected result" << std::endl;
    for (size_t i = 0; i < orig_list[0].size(); i++) // original에서 계속 가져와서 계산하니까 [0]으로 고정.
    {
        double x = orig_list[0][i];
        true_result8.push_back((x*x*x*x) + (2*x*x*x) + (3*x*x) + (4*x) + 2); //이거 change
    }
    orig_list.push_back(true_result8); //이것도 바뀌고
    crypt_list.push_back(cRes); //change
    name.push_back("cRes"); //change
    vecprint();
    strprint();
    //

    
   // a = cRes;
    Plaintext result;
   // Plaintext result;
    std::cout.precision(8);

    //plaintext 형태의 crypt_list
    for (size_t i = 0; i < crypt_list.size(); ++i) {
        cc->Decrypt(crypt_list[i], keys.secretKey, &result);
        result->SetLength(batchSize);
        std::cout<< "decrypt        " <<result<<std::endl;
    }

    //iw real_part를 뽑아낸 vec.
    std::vector<std::vector<double>> cryptvec_list;

    for (size_t i = 0; i < crypt_list.size(); ++i) {
        cc->Decrypt(crypt_list[i], keys.secretKey, &result);

        auto ckks_packed_value = result->GetCKKSPackedValue();

        std::vector<double> real_parts;
        std::transform(ckks_packed_value.begin(), ckks_packed_value.end(),
            std::back_inserter(real_parts),
            [](const std::complex<double>& c) {
                return c.real();
            }
        );

        cryptvec_list.push_back(real_parts);
    }

    //iw
    for (const auto& inner_vector : cryptvec_list) {
        std::cout << "--- ";
        for (const auto& element : inner_vector) {
            // std::cout << element << " ";
            printf("%.3f ", element);
        }
        std::cout << std::endl;
    }


    //iw error를 얻어내는 part
    std::vector<std::vector<double>> result_vec;

    if (cryptvec_list.size() == orig_list.size() && !cryptvec_list.empty()) {
        size_t rows = cryptvec_list.size();
        size_t cols = cryptvec_list[0].size();

        result_vec.resize(rows);
        for (size_t i = 0; i < rows; ++i) {
            result_vec[i].resize(cols);
            for (size_t j = 0; j < cols; ++j) {
                result_vec[i][j] = cryptvec_list[i][j] - orig_list[i][j];
            }
        }
    } else {
        std::cout << "Vectors have different sizes or are empty." << std::endl;
    }

    // Print the resulting vector
    for (const auto& row : result_vec) {
        for (double val : row) {
            std::cout << val << " ";
        }
        std::cout << std::endl;
    }



    //cc->Decrypt(cRes, keys.secretKey, &result1);
    //result1->SetLength(batchSize);
    //std::cout << "x^4 + 2x^3 + 3x^2 + 4*x + 2 = " << result1 << std::endl;

    //////////
    //uint32_t dnum = 2;
    cc->EvalRotateKeyGen(keys.secretKey, {2});
    auto cRot1         = cc->EvalRotate(cRes, 2);
    Plaintext r_result;
    std::cout.precision(8);

    cc->Decrypt(keys.secretKey, cRot1, &r_result);
    r_result->SetLength(batchSize);
    std::cout << "result rotate by 2 = " << r_result << std::endl;

}

void ManualRescaleDemo(ScalingTechnique scalTech) {
    
    std::cout << "\n\n\n ===== FixedManualDemo ============= " << std::endl;

    uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(5);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Input
    std::vector<double> x = {1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07};
    Plaintext ptxt        = cc->MakeCKKSPackedPlaintext(x);

    std::cout << "Input x: " << ptxt << std::endl;

    auto c = cc->Encrypt(keys.publicKey, ptxt);

    /* Computing f(x) = x^4 + 2x^3 + 3x^2 + 4*x + 2
    before x^18 + x^9 + 1
   *
   */
    // x^2
    auto c2_depth2 = cc->EvalMult(c, c);
    auto c2_depth1 = cc->Rescale(c2_depth2);
    // x^4
    auto c4_depth2 = cc->EvalMult(c2_depth1, c2_depth1);
    auto c4_depth1 = cc->Rescale(c4_depth2);
   
    // x^3
    auto c3_depth2 = cc->EvalMult(c2_depth1, c);
    auto c3_depth1 = cc->Rescale(c3_depth2);

    auto c3_depth1_1  = cc->EvalMult(c3_depth1, 2.0);
    auto c2_depth1_1 = cc->EvalMult(c2_depth1, 3.0);
    auto c1 = cc->EvalMult(c, 4.0);

    auto c34_depth1 = cc->EvalAdd(c4_depth1, c3_depth1_1);
    auto c12_depth1 = cc->EvalAdd(c2_depth1_1, c1);

    // Final result
    auto cRes_depth2 = cc->EvalAdd(cc->EvalAdd(c34_depth1, c12_depth1), 2.0);
    auto cRes_depth1 = cc->Rescale(cRes_depth2);

    Plaintext result2;
    std::cout.precision(8);

    cc->Decrypt(keys.secretKey, cRes_depth1, &result2);
    result2->SetLength(batchSize);
    std::cout << "x^4 + 2x^3 + 3x^2 + 4*x + 2" << result2 << std::endl;
}

void HybridKeySwitchingDemo1() {
   

    std::cout << "\n\n\n ===== HybridKeySwitchingDemo1 ============= " << std::endl;
    
    uint32_t dnum = 2;
    
    uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(5);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetNumLargeDigits(dnum);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl;

    std::cout << "- Using HYBRID key switching with " << dnum << " digits" << std::endl << std::endl;

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalRotateKeyGen(keys.secretKey, {2});

    // Input
    std::vector<double> x = {1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7};
    Plaintext ptxt        = cc->MakeCKKSPackedPlaintext(x);
   
   // what i wrote
   // Plaintext ptxt = a;
   // std::cout << "Input result: " << ptxt << std::endl;

    auto c = cc->Encrypt(keys.publicKey, ptxt);

    TimeVar t;
    TIC(t);
    auto cRot1         = cc->EvalRotate(c, 2);
    auto cRot2         = cc->EvalRotate(cRot1, 1);
    double time2digits = TOC(t);
    // Take note and compare the runtime to the runtime
    // of the same computation in the next demo.

    Plaintext result3;
    std::cout.precision(8);

    cc->Decrypt(keys.secretKey, cRot1, &result3);
    result3->SetLength(batchSize);
    std::cout << "result rotate by 2 = " << result3 << std::endl;
    std::cout << " 2 rotations with HYBRID (2 digits) took " << time2digits << "ms" << std::endl;

    
}


void vecprint(){
    //vector print iw
    for (const auto& inner_vector : orig_list) {
        std::cout << "- ";
        for (const auto& element : inner_vector) {
            // std::cout << element << " ";
            printf("%.3f ", element);
        }
        std::cout << std::endl;
    }

}


void strprint(){
    for (const auto& str : name) {
        std::cout << str << " ";
    }
    std::cout << std::endl;

}

//void errprint(const lbcrypto::secretKey<lbcrypto::DCRTPoly>& secretKey, const CryptoContext<lbcrypto::DCRTPoly>& cc) {
//    std::cout << "error print" << std::endl;
//    Plaintext result1;
//    for (size_t i = 0; i < crypt_list.size(); ++i) {
//        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext = crypt_list[i];
//        cc->Decrypt(ciphertext, keys.secretKey, &result1);
//        result1->SetLength(batchSize);
        
//    }
//}
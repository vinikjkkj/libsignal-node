#include <napi.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>

extern "C" {
    int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);
    int curve25519_sign(uint8_t *signature, const uint8_t *curve25519_privkey,
                       const uint8_t *msg, const size_t msg_len);
    int curve25519_verify(const uint8_t *signature, const uint8_t *curve25519_pubkey,
                         const uint8_t *msg, const size_t msg_len);
}

enum TaskType { DONNA, SIGN, VERIFY };

class Task : public Napi::AsyncWorker {
public:
    std::vector<uint8_t> input1;
    std::vector<uint8_t> input2;
    std::vector<uint8_t> input3;
    size_t input3_len;
    TaskType type;
    std::vector<uint8_t> result;
    bool success;

    Task(Napi::Function& callback, const std::vector<uint8_t>& i1, 
         const std::vector<uint8_t>& i2, TaskType t)
        : Napi::AsyncWorker(callback), input1(i1), input2(i2), type(t) {}

    Task(Napi::Function& callback, const std::vector<uint8_t>& i1,
         const std::vector<uint8_t>& i2, const std::vector<uint8_t>& i3)
        : Napi::AsyncWorker(callback), input1(i1), input2(i2), input3(i3),
          input3_len(i3.size()), type(VERIFY) {}

protected:
    void Execute() override {
        switch (type) {
            case DONNA: {
                result.resize(32);
                success = curve25519_donna(result.data(), input1.data(), input2.data()) == 0;
                break;
            }
            case SIGN: {
                result.resize(64);
                success = curve25519_sign(result.data(), input1.data(), input2.data(), input2.size()) == 0;
                break;
            }
            case VERIFY: {
                success = curve25519_verify(input1.data(), input2.data(), input3.data(), input3_len) == 0;
                break;
            }
        }
    }

    void OnOK() override {
        Napi::HandleScope scope(Env());
        
        if (type == VERIFY) {
            Callback().Call({Env().Null(), Napi::Boolean::New(Env(), success)});
        } else {
            auto resultBuffer = Napi::Buffer<uint8_t>::Copy(Env(), result.data(), result.size());
            Callback().Call({Env().Null(), resultBuffer});
        }
    }

    void OnError(const Napi::Error& e) override {
        Napi::HandleScope scope(Env());
        Callback().Call({e.Value(), Env().Undefined()});
    }
};

Napi::Value Curve25519_Donna(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 3) {
        Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsBuffer() || !info[1].IsBuffer() || !info[2].IsFunction()) {
        Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    auto secret = info[0].As<Napi::Buffer<uint8_t>>();
    auto basepoint = info[1].As<Napi::Buffer<uint8_t>>();
    auto callback = info[2].As<Napi::Function>();
    
    if (secret.Length() != 32 || basepoint.Length() != 32) {
        Napi::TypeError::New(env, "Inputs must be 32 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }

    auto worker = new Task(
        callback,
        std::vector<uint8_t>(secret.Data(), secret.Data() + secret.Length()),
        std::vector<uint8_t>(basepoint.Data(), basepoint.Data() + basepoint.Length()),
        DONNA
    );
    worker->Queue();
    return env.Undefined();
}

Napi::Value Curve25519_Sign(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 3) {
        Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsBuffer() || !info[1].IsBuffer() || !info[2].IsFunction()) {
        Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    auto privkey = info[0].As<Napi::Buffer<uint8_t>>();
    auto msg = info[1].As<Napi::Buffer<uint8_t>>();
    auto callback = info[2].As<Napi::Function>();

    auto worker = new Task(
        callback,
        std::vector<uint8_t>(privkey.Data(), privkey.Data() + privkey.Length()),
        std::vector<uint8_t>(msg.Data(), msg.Data() + msg.Length()),
        SIGN
    );
    worker->Queue();
    return env.Undefined();
}

Napi::Value Curve25519_Verify(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 4) {
        Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsBuffer() || !info[1].IsBuffer() || !info[2].IsBuffer() || !info[3].IsFunction()) {
        Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    auto signature = info[0].As<Napi::Buffer<uint8_t>>();
    auto pubkey = info[1].As<Napi::Buffer<uint8_t>>();
    auto msg = info[2].As<Napi::Buffer<uint8_t>>();
    auto callback = info[3].As<Napi::Function>();

    auto worker = new Task(
        callback,
        std::vector<uint8_t>(signature.Data(), signature.Data() + signature.Length()),
        std::vector<uint8_t>(pubkey.Data(), pubkey.Data() + pubkey.Length()),
        std::vector<uint8_t>(msg.Data(), msg.Data() + msg.Length())
    );
    worker->Queue();
    return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("curve25519_donna", Napi::Function::New(env, Curve25519_Donna));
    exports.Set("curve25519_sign", Napi::Function::New(env, Curve25519_Sign));
    exports.Set("curve25519_verify", Napi::Function::New(env, Curve25519_Verify));
    return exports;
}

NODE_API_MODULE(signal_crypto, Init)

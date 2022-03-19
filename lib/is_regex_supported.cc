#include <string>
#include <nan.h>
#include <re2/re2.h>

NAN_METHOD(IsRegexSupported) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

  if (info.Length() != 1 || !info[0]->IsObject() || info[0].IsEmpty()) {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }

  auto regex_options = info[0]->ToObject(context).ToLocalChecked();

  auto regex_key = Nan::New<v8::String>("regex").ToLocalChecked();
  auto is_case_sensitive_key = Nan::New<v8::String>("isCaseSensitive").ToLocalChecked();
  auto require_capturing_key = Nan::New<v8::String>("requireCapturing").ToLocalChecked();

  if (!regex_options->Has(context, regex_key).ToChecked()) {
    Nan::ThrowTypeError("Wrong arguments");
    return;
  }

  std::string pattern = *Nan::Utf8String(regex_options->Get(context, regex_key).ToLocalChecked());

  bool is_case_sensitive = true;
  bool require_capturing = false;

  if (regex_options->Has(context, is_case_sensitive_key).ToChecked())
    is_case_sensitive = Nan::To<bool>(regex_options->Get(context, is_case_sensitive_key).ToLocalChecked()).FromJust();
  if (regex_options->Has(context, require_capturing_key).ToChecked())
    require_capturing = Nan::To<bool>(regex_options->Get(context, require_capturing_key).ToLocalChecked()).FromJust();

  // Mirror the options which the declarativeNetRequest code uses, see
  // https://source.chromium.org/chromium/chromium/src/+/master:extensions/browser/api/declarative_net_request/utils.cc;l=232-253
  re2::RE2::Options options;
  options.set_encoding(re2::RE2::Options::EncodingLatin1);
  options.set_case_sensitive(is_case_sensitive);
  options.set_never_capture(!require_capturing);
  options.set_log_errors(false);
  options.set_max_mem(2 << 10);

  re2::RE2 regex(pattern, options);

  v8::Local<v8::Object> result = Nan::New<v8::Object>();
  Nan::Set(result,
           Nan::New("isSupported").ToLocalChecked(),
           Nan::New(regex.ok()));

  if (!regex.ok()) {
    Nan::Set(result,
             Nan::New("reason").ToLocalChecked(),
             Nan::New(regex.error_code() == re2::RE2::ErrorPatternTooLarge
                          ? "memoryLimitExceeded" : "syntaxError").ToLocalChecked());
  }

  info.GetReturnValue().Set(result);
}

NAN_MODULE_INIT(Init) {
  Nan::Set(target,
           Nan::New<v8::String>("isRegexSupported").ToLocalChecked(),
           Nan::GetFunction(Nan::New<v8::FunctionTemplate>(IsRegexSupported)).ToLocalChecked());
}

NODE_MODULE(addon, Init)

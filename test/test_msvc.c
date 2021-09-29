// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "demangling_unit.h"

bool demangle(void) {
	mu_demangle(msvc, ".?AV?$_CancellationTokenCallback@Vlambda_1@?1??_RegisterCancellation@_Task_impl_base@details@Concurrency@@QEAAXV?$weak_ptr@U_Task_impl_base@details@Concurrency@@@std@@@Z@@details@Concurrency@@", "class Concurrency::details::_CancellationTokenCallback<class `public: void __cdecl Concurrency::details::_Task_impl_base::_RegisterCancellation(class std::weak_ptr<struct Concurrency::details::_Task_impl_base>) __ptr64'::`2'::lambda_1>");
	mu_demangle(msvc, ".?AV?$FunctionT@P6AXPAX@Z@ns@@", "class ns::FunctionT<void (__cdecl *)(void *)>");
	mu_demangle(msvc, ".?AV?$GHI@$00VPQR@MNO@JKL@@@DEF@ABC@@", "class ABC::DEF::GHI<1, class JKL::MNO::PQR>");
	mu_demangle(msvc, ".?AV?$GHI@$FB@C@VPQR@MNO@JKL@@@DEF@ABC@@", "class ABC::DEF::GHI<{1, 2}, class JKL::MNO::PQR>");
	mu_demangle(msvc, ".?AV?$GHI@$GB@C@D@VPQR@MNO@JKL@@@DEF@ABC@@", "class ABC::DEF::GHI<{1, 2, 3}, class JKL::MNO::PQR>");
	mu_demangle(msvc, ".?AV?$GHI@$H0VPQR@MNO@JKL@@@DEF@ABC@@", "class ABC::DEF::GHI<1, class JKL::MNO::PQR>");
	mu_demangle(msvc, ".?AV?$GHI@$IB@C@VPQR@MNO@JKL@@@DEF@ABC@@", "class ABC::DEF::GHI<{1, 2}, class JKL::MNO::PQR>");
	mu_demangle(msvc, ".?AV?$GHI@$JB@C@D@VPQR@MNO@JKL@@@DEF@ABC@@", "class ABC::DEF::GHI<{1, 2, 3}, class JKL::MNO::PQR>");
	mu_demangle(msvc, ".?AV?$Template@UUnnamedStruct@@$1?StructName1@@3UStructType1@@B$1?StructName2@@3U3@B$00$0A@VChildClass@Class@@@Class@@", "class Class::Template<struct UnnamedStruct, &struct StructType1 const StructName1, &struct StructType1 const StructName2, 1, 0, class Class::ChildClass>");
	mu_demangle(msvc, ".?AVClassInInnerNamespace@InnerNamespace@OuterNamespace@@", "class OuterNamespace::InnerNamespace::ClassInInnerNamespace");
	mu_demangle(msvc, "??$?RD@ABC@@QEBAXQEBD@Z", "public: void __cdecl ABC::operator()<char>(char const * const __ptr64)const __ptr64");
	mu_demangle(msvc, "??$invoke@P6AXPEAX@ZAEAPEAX@wistd@@YAX$$REAP6AXPEAX@ZAEAPEAX@Z", "void __cdecl wistd::invoke<void (__cdecl *)(void * __ptr64), void * __ptr64 & __ptr64>(void (__cdecl *)(void * __ptr64) && volatile __ptr64, void * __ptr64 & __ptr64)");
	mu_demangle(msvc, "??$MyTemplateFunction@VClass1@@@Class1@@QAEXPAV0@@Z", "public: void __thiscall Class1::MyTemplateFunction<class Class1>(class Class1 *)");
	mu_demangle(msvc, "??0Delegate@Platform@@QE$AAA@XZ", "public: void __cdecl Platform::Delegate::constructor(void) __ptr64");
	mu_demangle(msvc, "??0PoolingFwdFP16x2Shader@cask@@QEAA@PEBVKernelInfo@1@Q6A?AV?$SafeEnum@UErrorEnum@cask@@@1@AEAUpoolingDescription@PoolingOperation@1@PEBXPEAXPEAUCUstream_st@@AEAW4cudaError@@@Z@Z", "public: void __cdecl cask::PoolingFwdFP16x2Shader::constructor(class cask::KernelInfo const * __ptr64, class cask::SafeEnum<struct cask::ErrorEnum> (__cdecl * const)(struct cask::PoolingOperation::poolingDescription & __ptr64, void const * __ptr64, void * __ptr64, struct CUstream_st * __ptr64, enum cudaError & __ptr64)) __ptr64");
	mu_demangle(msvc, "??0TEST_CLASS@@QEAA@AEBV0@@Z", "public: void __cdecl TEST_CLASS::constructor(class TEST_CLASS const & __ptr64) __ptr64");
	mu_demangle(msvc, "??0TEST_CLASS@@QEAA@H@Z", "public: void __cdecl TEST_CLASS::constructor(int) __ptr64");
	mu_demangle(msvc, "??1?$_Func_class@XW4LaunchUriStatus@System@Windows@@U_Nil@std@@U45@@std@@QEAA@XZ", "public: void __cdecl std::_Func_class<void, enum Windows::System::LaunchUriStatus, struct std::_Nil, struct std::_Nil>::~destructor(void) __ptr64");
	mu_demangle(msvc, "??1TEST_CLASS@@QEAA@XZ", "public: void __cdecl TEST_CLASS::~destructor(void) __ptr64");
	mu_demangle(msvc, "??4TEST_CLASS@@QEAAAEAV0@AEBV0@@Z ", "public: class TEST_CLASS & __ptr64 __cdecl TEST_CLASS::operator=(class TEST_CLASS const & __ptr64) __ptr64");
	mu_demangle(msvc, "??_7?$_Func_impl@U?$_Callable_obj@Vlambda@@$0A@@std@@V?$allocator@V?$_Func_class@XU_Nil@std@@U12@@std@@@2@XU_Nil@2@U42@@std@@6B@", "const std::_Func_impl<struct std::_Callable_obj<class lambda, 0>, class std::allocator<class std::_Func_class<void, struct std::_Nil, struct std::_Nil>>, void, struct std::_Nil, struct std::_Nil>::vftable");
	mu_demangle(msvc, "??_7NetworkUXViewProviderImpl@@6BIWeakReferenceSource@@@", "const NetworkUXViewProviderImpl::vftable{for `IWeakReferenceSource'}");
	mu_demangle(msvc, "??_7OOBEMainPage@NetworkUX@@6B__abi_IUnknown@@IWeakReferenceSource@Details@Platform@@@", "const NetworkUX::OOBEMainPage::vftable{for `__abi_IUnknown's `Platform::Details::IWeakReferenceSource'}");
	mu_demangle(msvc, "??_G?$__func@Vlambda@@$$A6AJPEBVExtensionRegistration@Details@PlatformExtensions@Internal@Windows@@_NPEA_N@Z@__function@wistd@@UEAAPEAXI@Z", "public virtual: void * __ptr64 __cdecl wistd::__function::__func<class lambda, long int (__cdecl *)(class Windows::Internal::PlatformExtensions::Details::ExtensionRegistration const * __ptr64, bool, bool * __ptr64)>::scalar_dtor(unsigned int) __ptr64");
	mu_demangle(msvc, "??_G?$impl@V?$binder2@V?$io_op@V?$basic_stream_socket@Vtcp@ip@asio@boost@@V?$any_executor@U?$context_as_t@AEAVexecution_context@asio@boost@@@execution@asio@boost@@U?$never_t@$0A@@blocking@detail@234@U?$prefer_only@U?$possibly_t@$0A@@blocking@detail@execution@asio@boost@@@234@U?$prefer_only@U?$tracked_t@$0A@@outstanding_work@detail@execution@asio@boost@@@234@U?$prefer_only@U?$untracked_t@$0A@@outstanding_work@detail@execution@asio@boost@@@234@U?$prefer_only@U?$fork_t@$0A@@relationship@detail@execution@asio@boost@@@234@U?$prefer_only@U?$continuation_t@$0A@@relationship@detail@execution@asio@boost@@@234@@execution@34@@asio@boost@@V?$read_op@Vmutable_buffers_1@asio@boost@@@detail@ssl@23@V?$read_op@V?$stream@V?$basic_stream_socket@Vtcp@ip@asio@boost@@V?$any_executor@U?$context_as_t@AEAVexecution_context@asio@boost@@@execution@asio@boost@@U?$never_t@$0A@@blocking@detail@234@U?$prefer_only@U?$possibly_t@$0A@@blocking@detail@execution@asio@boost@@@234@U?$prefer_only@U?$tracked_t@$0A@@outstanding_work@detail@execution@asio@boost@@@234@U?$prefer_only@U?$untracked_t@$0A@@outstanding_work@detail@execution@asio@boost@@@234@U?$prefer_only@U?$fork_t@$0A@@relationship@detail@execution@asio@boost@@@234@U?$prefer_only@U?$continuation_t@$0A@@relationship@detail@execution@asio@boost@@@234@@execution@34@@asio@boost@@@ssl@asio@boost@@Vmutable_buffers_1@34@PEBVmutable_buffer@34@Vtransfer_at_least_t@detail@34@V?$wrapped_handler@Vstrand@io_context@asio@boost@@V?$custom_alloc_handler@V?$_Binder@U_Unforced@std@@P8?$connection@Utransport_config@asio_tls@config@websocketpp@@@asio@transport@websocketpp@@EAAXV?$function@$$A6AXAEBVerror_code@std@@_K@Z@2@AEBVerror_code@system@boost@@_K@ZV?$shared_ptr@V?$connection@Utransport_config@asio_tls@config@websocketpp@@@asio@transport@websocketpp@@@2@AEAV72@AEBU?$_Ph@$00@2@AEBU?$_Ph@$01@2@@std@@@3transport@websocketpp@@Uis_continuation_if_running@detail@34@@834@@523@@detail@ssl@asio@boost@@Verror_code@system@5@_K@detail@asio@boost@@V?$allocator@X@std@@@executor_function@detail@asio@boost@@QEAAPEAXI@Z", "public: void * __ptr64 __cdecl boost::asio::detail::executor_function::impl<class boost::asio::detail::binder2<class boost::asio::ssl::detail::io_op<class boost::asio::basic_stream_socket<class boost::asio::ip::tcp, class boost::asio::execution::any_executor<struct boost::asio::execution::context_as_t<class boost::asio::execution_context & __ptr64>, struct boost::asio::execution::detail::blocking::never_t<0>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::blocking::possibly_t<0>>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::outstanding_work::tracked_t<0>>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::outstanding_work::untracked_t<0>>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::relationship::fork_t<0>>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::relationship::continuation_t<0>>>>, class boost::asio::ssl::detail::read_op<class boost::asio::mutable_buffers_1>, class boost::asio::detail::read_op<class boost::asio::ssl::stream<class boost::asio::basic_stream_socket<class boost::asio::ip::tcp, class boost::asio::execution::any_executor<struct boost::asio::execution::context_as_t<class boost::asio::execution_context & __ptr64>, struct boost::asio::execution::detail::blocking::never_t<0>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::blocking::possibly_t<0>>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::outstanding_work::tracked_t<0>>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::outstanding_work::untracked_t<0>>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::relationship::fork_t<0>>, struct boost::asio::execution::prefer_only<struct boost::asio::execution::detail::relationship::continuation_t<0>>>>>, class boost::asio::mutable_buffers_1, class boost::asio::mutable_buffer const * __ptr64, class boost::asio::detail::transfer_at_least_t, class boost::asio::detail::wrapped_handler<class boost::asio::io_context::strand, class websocketpp::transport::asio::custom_alloc_handler<class std::_Binder<struct std::_Unforced, void & (__thiscall websocketpp::transport::asio::connection<struct websocketpp::config::asio_tls::transport_config>::*)(class std::function<void (__cdecl *)(class std::error_code const & __ptr64, unsigned long long(unsigned __int64))>, class boost::system::error_code const & __ptr64, unsigned long long(unsigned __int64)), class std::shared_ptr<class websocketpp::transport::asio::connection<struct websocketpp::config::asio_tls::transport_config>>, class std::function<void (__cdecl *)(class std::error_code const & __ptr64, unsigned long long(unsigned __int64))> & __ptr64, struct std::_Ph<1> const & __ptr64, struct std::_Ph<2> const & __ptr64>>, struct boost::asio::detail::is_continuation_if_running>>>, class boost::system::error_code, unsigned long long(unsigned __int64)>, class std::allocator<void>>::scalar_dtor(unsigned int) __ptr64");
	mu_demangle(msvc, "??_R0?AVResultException@wil@@@8", "class wil::ResultException `RTTI Type Descriptor'");
	mu_demangle(msvc, "??B?$ABC@DUDEF@@@@QEBA_NXZ", "public: bool __cdecl ABC<char, struct DEF>::operator bool(void)const __ptr64");
	mu_demangle(msvc, "??B?$unique_any_t@V?$semaphore_t@V?$unique_storage@U?$resource_policy@PEAXP6AXPEAX@Z$1?CloseHandle@details@wil@@YAX0@ZU?$integral_constant@_K$0A@@wistd@@PEAXPEAX$0A@$$T@details@wil@@@details@wil@@Uerr_returncode_policy@3@@wil@@@wil@@QEBA_NXZ", "public: bool __cdecl wil::unique_any_t<class wil::semaphore_t<class wil::details::unique_storage<struct wil::details::resource_policy<void * __ptr64, void (__cdecl *)(void * __ptr64), &void __cdecl wil::details::CloseHandle(void * __ptr64), struct wistd::integral_constant<unsigned long long(unsigned __int64), 0>, void * __ptr64, void * __ptr64, 0, std::nullptr_t>>, struct wil::err_returncode_policy>>::operator bool(void)const __ptr64");
	mu_demangle(msvc, "??HTEST_CLASS@@QEAA?AV0@AEBV0@@Z ", "public: class TEST_CLASS __cdecl TEST_CLASS::operator+(class TEST_CLASS const & __ptr64) __ptr64");
	mu_demangle(msvc, "?__abi_Release@?QObject@Platform@@__CFEWiFiWCNComboActivationFactory@View@NetworkUX@@W7E$AAAKXZ", "[thunk]:public virtual: unsigned long int __cdecl NetworkUX::View::__CFEWiFiWCNComboActivationFactory::[Platform::Object]::__abi_Release`adjustor{8}'(void) __ptr64");
	mu_demangle(msvc, "?_tlgEvent@?M@??ReportStopActivity@?$ActivityBase@VNetworkFlyoutLogging@@$00$0A@$04$0A@U_TlgReflectorTag_Param0IsProviderType@@@wil@@AEAAXJ@Z@4Uunnamed-type-_tlgEvent@?M@??123@AEAAXJ@Z@B", "struct `private: void __cdecl wil::ActivityBase<class NetworkFlyoutLogging, 1, 0, 5, 0, struct _TlgReflectorTag_Param0IsProviderType>::ReportStopActivity(long int) __ptr64'::`12'::unnamed-type-_tlgEvent const `private: void __cdecl wil::ActivityBase<class NetworkFlyoutLogging, 1, 0, 5, 0, struct _TlgReflectorTag_Param0IsProviderType>::ReportStopActivity(long int) __ptr64'::`12'::_tlgEvent");
	mu_demangle(msvc, "?AbbreviationOfRepeteadNames@@YAPEAVTEST_CLASS@@PEAV1@00AEAV1@@Z", "class TEST_CLASS * __ptr64 __cdecl AbbreviationOfRepeteadNames(class TEST_CLASS * __ptr64, class TEST_CLASS * __ptr64, class TEST_CLASS * __ptr64, class TEST_CLASS & __ptr64)");
	mu_demangle(msvc, "?AbbreviationOfRepeteadTypes@@YA_NPEAHHH0_N1PEA_N@Z", "bool __cdecl AbbreviationOfRepeteadTypes(int * __ptr64, int, int, int * __ptr64, bool, bool, bool * __ptr64)");
	mu_demangle(msvc, "?arr2@@3PAY07HA", "int (*)[8] arr2");
	mu_demangle(msvc, "?arr3@@3PAY1BA@4HA", "int (*)[16][5] arr3");
	mu_demangle(msvc, "?arr@@3PAHA", "int * arr");
	mu_demangle(msvc, "?Delegate@Platform@@YAPE$AAVString@Platform@@_NPE$AAVObject@3@@Z", "class Platform::String ^ __ptr64 __cdecl Platform::Delegate(bool, class Platform::Object ^ __ptr64)");
	mu_demangle(msvc, "?f1@@YAXTUNION_TEST@1@0@Z", "void __cdecl f1(union UNION_TEST::UNION_TEST, union UNION_TEST::UNION_TEST)");
	mu_demangle(msvc, "?f2@@YAXTUNION_TEST@1@VTEST@2@0@Z", "void __cdecl f2(union UNION_TEST::UNION_TEST, class TEST::TEST, union UNION_TEST::UNION_TEST)");
	mu_demangle(msvc, "?f3@@YAXTUNION_TEST_NEW@@@Z", "void __cdecl f3(union UNION_TEST_NEW)");
	mu_demangle(msvc, "?f4@@YAXTUNION_NAMESPACE_2@NAMESPACE_2@NAMESPACE_1@@VTEST@4@TUNION_TEST@5@@Z", "void __cdecl f4(union NAMESPACE_1::NAMESPACE_2::UNION_NAMESPACE_2, class TEST::TEST, union UNION_TEST::UNION_TEST)");
	mu_demangle(msvc, "?f5@@YAXTUNION_TEST@1NAMESPACE_1@@VTEST@3@T11@@Z", "void __cdecl f5(union NAMESPACE_1::UNION_TEST::UNION_TEST, class TEST::TEST, union UNION_TEST::UNION_TEST)");
	mu_demangle(msvc, "?func_with_arg_class_from_namespace@@YAXVTEST@1@@Z", "void __cdecl func_with_arg_class_from_namespace(class TEST::TEST)");
	mu_demangle(msvc, "?func_with_arg_union_from_namespace@@YAXTUNION_TEST@1@@Z", "void __cdecl func_with_arg_union_from_namespace(union UNION_TEST::UNION_TEST)");
	mu_demangle(msvc, "?Fx_i@@YAHP6AHH@Z@Z", "int __cdecl Fx_i(int (__cdecl *)(int))");
	mu_demangle(msvc, "?Fxix_i@@YAHP6AHH@ZH0@Z", "int __cdecl Fxix_i(int (__cdecl *)(int), int, int (__cdecl *)(int))");
	mu_demangle(msvc, "?Fxyxy_i@@YAHP6AHH@ZP6AHF@Z01@Z", "int __cdecl Fxyxy_i(int (__cdecl *)(int), int (__cdecl *)(short int), int (__cdecl *)(int), int (__cdecl *)(short int))");
	mu_demangle(msvc, "?Fxyxy_i_x64@@YAHP6AHPEAH0H@ZP6AH0H0@ZP6AHH@ZP6AHF@Z@Z", "int __cdecl Fxyxy_i_x64(int (__cdecl *)(int * __ptr64, int * __ptr64, int), int (__cdecl *)(int * __ptr64, int, int * __ptr64), int (__cdecl *)(int), int (__cdecl *)(short int))");
	mu_demangle(msvc, "?instance_@?$StaticStorage@VInProcModule@Details@Platform@@$0A@H@Details@WRL@Microsoft@@0V1234@A", "class Microsoft::WRL::Details::StaticStorage<class Platform::Details::InProcModule, 0, int> Microsoft::WRL::Details::StaticStorage<class Platform::Details::InProcModule, 0, int>::instance_");
	mu_demangle(msvc, "?private_func@TEST_CLASS@@AEAAXXZ", "private: void __cdecl TEST_CLASS::private_func(void) __ptr64");
	mu_demangle(msvc, "?public_func@TEST_CLASS@@QEAAHXZ", "public: int __cdecl TEST_CLASS::public_func(void) __ptr64");
	mu_demangle(msvc, "?SomeFunction@@YAPAVClass1@@PAV1@PAVClass2@@1AAV2@@Z", "class Class1 * __cdecl SomeFunction(class Class1 *, class Class2 *, class Class2 *, class Class2 &)");
	mu_demangle(msvc, "?static_func@TEST_CLASS@@SAXH@Z", "public: static void __cdecl TEST_CLASS::static_func(int)");
	mu_demangle(msvc, "?test@@$$FYMHPE$AA__ZUV@@@Z", "int __clrcall test(struct V ^ __ptr64)");
	mu_demangle(msvc, "?test@@$$FYMHPE$CA__ZUV@@@Z", "int __clrcall test(struct V % __ptr64)");
	mu_demangle(msvc, "?test@@YMHAE$CAPEAUV@@@Z", "int __clrcall test(struct V * __ptr64 % __ptr64)");
	mu_demangle(msvc, "?var__m128@@3T__m128@@A", "__m128 var__m128");
	mu_demangle(msvc, "?var__m128d@@3U__m128d@@A", "__m128d var__m128d");
	mu_demangle(msvc, "?var__m128i@@3T__m128i@@A", "__m128i var__m128i");
	mu_demangle(msvc, "?var__m256@@3T__m256@@A", "__m256 var__m256");
	mu_demangle(msvc, "?var__m256d@@3U__m256d@@A", "__m256d var__m256d");
	mu_demangle(msvc, "?var__m256i@@3T__m256i@@A", "__m256i var__m256i");
	mu_demangle(msvc, "?var__m64@@3T__m64@@A", "__m64 var__m64");
	mu_demangle(msvc, "?var_bool@@3_NA", "bool var_bool");
	mu_demangle(msvc, "?var_char@@3DA", "char var_char");
	mu_demangle(msvc, "?var_class@@3VCLASS_TEST@@A", "class CLASS_TEST var_class");
	mu_demangle(msvc, "?var_class_with_namespace@TEST_NAMESPACE@@3VCLASS_TEST@@A", "class CLASS_TEST TEST_NAMESPACE::var_class_with_namespace");
	mu_demangle(msvc, "?var_const_int_ptr@@3PEBHEB", "int const * __ptr64 const __ptr64 var_const_int_ptr");
	mu_demangle(msvc, "?var_const_volatile_int_ptr@@3PEDHED", "int const volatile * __ptr64 const volatile __ptr64 var_const_volatile_int_ptr");
	mu_demangle(msvc, "?var_double@@3NA", "double var_double");
	mu_demangle(msvc, "?var_enum@@3W4ENUM_TEST@@A", "enum ENUM_TEST var_enum");
	mu_demangle(msvc, "?var_enum_with_namespace@TEST_NAMESPACE@@3W4ENUM_TEST@@A", "enum ENUM_TEST TEST_NAMESPACE::var_enum_with_namespace");
	mu_demangle(msvc, "?var_float@@3MA", "float var_float");
	mu_demangle(msvc, "?var_int@@3HA", "int var_int");
	mu_demangle(msvc, "?var_int_ptr@@3PEAHA", "int * __ptr64 var_int_ptr");
	mu_demangle(msvc, "?var_int_ptr_volatile@@3REAHEA", "int * volatile __ptr64 __ptr64 var_int_ptr_volatile");
	mu_demangle(msvc, "?var_long_double@@3OA", "long double var_long_double");
	mu_demangle(msvc, "?var_long_int@@3JA", "long int var_long_int");
	mu_demangle(msvc, "?var_long_long@@3_JA", "long long(__int64) var_long_long");
	mu_demangle(msvc, "?var_ptr_with_namespace@TEST_NAMESPACE@@3PEAUSTRUCT_TEST@@EA", "struct STRUCT_TEST * __ptr64 __ptr64 TEST_NAMESPACE::var_ptr_with_namespace");
	mu_demangle(msvc, "?var_short_int@@3FA", "short int var_short_int");
	mu_demangle(msvc, "?var_signed_char@@3CA", "signed char var_signed_char");
	mu_demangle(msvc, "?var_union@@3TUNION_TEST@@A", "union UNION_TEST var_union");
	mu_demangle(msvc, "?var_union_with_namespace@TEST_NAMESPACE@@3TUNION_TEST@@A", "union UNION_TEST TEST_NAMESPACE::var_union_with_namespace");
	mu_demangle(msvc, "?var_unsigned_char@@3EA", "unsigned char var_unsigned_char");
	mu_demangle(msvc, "?var_unsigned_int@@3IA", "unsigned int var_unsigned_int");
	mu_demangle(msvc, "?var_unsigned_long_int@@3KA", "unsigned long int var_unsigned_long_int");
	mu_demangle(msvc, "?var_unsigned_long_long@@3_KA", "unsigned long long(unsigned __int64) var_unsigned_long_long");
	mu_demangle(msvc, "?var_voidptr@@3PEAXA", "void * __ptr64 var_voidptr");
	mu_demangle(msvc, "?var_volatile_int_ptr@@3PECHEC", "int volatile * __ptr64 volatile __ptr64 var_volatile_int_ptr");
	mu_demangle(msvc, "?var_wchar_t@@3_WA", "wchar_t var_wchar_t");
	mu_demangle(msvc, "?xyz@?$abc@V?$def@H@@PAX@@YAXXZ", "void __cdecl abc<class def<int>, void *>::xyz(void)");

	mu_end;
}

int all_tests() {
	mu_run_test(demangle);
	return tests_passed != tests_run;
}

mu_main(all_tests)

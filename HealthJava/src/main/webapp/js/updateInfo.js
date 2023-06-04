
function update_check(){
   
   if($.trim($("#user_name").val())==""){
      alert("회원이름을 입력하세요!");
      $("#user_name").val("").focus();
      return false;
   }
     let regexName = /^[ㄱ-힣]{2,4}$/;
     if(!regexName.test($("#user_name").val())){
      alert("회원이름은 한글로 2~4자내로 입력해주세요!");
      $("#user_name").val("").focus();
      return false;
   }
   if($.trim($("#user_birth").val())==""){
      alert("생년월일 입력하세요!");      
      return false;
   }
    let regexBirth = /^([0-9][0-9]|\d{2})(0[0-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1])$/;
    if(!regexBirth.test($("#user_birth").val())){
      alert("생년월일은 예)1999년 1월 1일 -> 990101로 입력해주세요");      
      $("#user_birth").val("").focus();
      return false;
   }
   
   
   if($.trim($("#user_gender").val())==""){
      alert("성별을 입력하세요!");      
      return false;
   }
	let regexGender = /^(male|female|남자|여자)$/i; // 정규식 패턴
	if (!regexGender.test($("#user_gender").val())) {
		alert(" 'male', 'female', '남자', '여자'로만 입력해주세요 (대소문자 구분 없음)");
		$("user_gender").val("").focus();
		return false;
	} 

   if($.trim($("#postCode").val())==""){
      alert("우편번호를 입력하세요!");      
      return false;
   }
   if($.trim($("#roadAddr").val())==""){
      alert("주소를 입력하세요!");      
      return false;
   }
   if($.trim($("#detailAddr").val())==""){
      alert("나머지 주소를 입력하세요!");
      $("#detailAddr").val("").focus();
      return false;
   }

   if($.trim($("#user_phone").val())==""){
      alert("폰번호를 입력하세요!");
      $("#user_phone").val("").focus();
      return false;
   }
     let regexPhone = /^[0-9]{11}$/;
    if(!regexPhone.test($("#user_phone").val())){
      alert("폰번호는 예)010-1234-5678 -> 01012345678로 입력해주세요!");
      $("#user_phone").val("").focus();
      return false;
   }
   
	alert("정보 수정 성공!");
   return true;
}


function pwd_check(){
	$user_pwd=$.trim($("#user_pwd").val());
	$new_pwd=$.trim($("#new_pwd").val());
	$new_pwd_check=$.trim($("#new_pwd_check").val());
	
	if($.trim($("#user_pwd").val())==""){
		alert("현재 비밀번호를 입력하세요!");
		$("#user_pwd").val("").focus();
		return false;
	}
	 
	if($.trim($("#new_pwd").val())==""){
		alert("새 비밀번호를 입력하세요!");
		$("#new_pwd").val("").focus();
		return false;
	}
	if($new_pwd.length<8) {
      alert("비밀번호는 8자 이상 입력 해야합니다.")
      $("#new_pwd").val("").focus();
      return false;
      
   }
	if($.trim($("#new_pwd_check").val())==""){
		alert("새 비밀번호 확인을 입력하세요!");
		$("#new_pwd_check").val("").focus();
		return false;
	}
	if($new_pwd != $new_pwd_check){
		alert("새 비밀번호 확인이 다릅니다!");
		$("#new_pwd").val("");
		$("#new_pwd_check").val("");
		$("#user_pwd_check").focus();
		return false;
	}
	
   
   alert("비밀번호가 변경되었습니다")
   return true;
	
	
}

function withdrawal_check(){
	$user_id=$.trim($("#user_id").val());
	$user_pwd=$.trim($("#user_pwd").val());
	//$user_pwd_check=$.trim($("#user_pwd_check").val());
	
	if($.trim($("#user_id").val())==""){
		alert("아이디를 입력하세요!");
		$("#user_id").val("").focus();
		return false;
	}
	
	if($.trim($("#user_pwd").val())==""){
		alert("비밀번호를 입력하세요!");
		$("#user_pwd").val("").focus();
		return false;
	}
	/* 
	if($.trim($("#user_pwd_check").val())==""){
		alert("비밀번호 확인을 입력하세요!");
		$("#user_pwd_check").val("").focus();
		return false;
	}
	if($user_pwd != $user_pwd_check){
		alert("비밀번호가 다릅니다!");
		$("#user_pwd").val("");
		$("#user_pwd_check").val("");
		$("#user_pwd").focus();
		return false;
	}
*/
 alert("회원탈퇴가 완료 되었습니다!");
 return true;

}































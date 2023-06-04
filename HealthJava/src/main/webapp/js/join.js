/**
 * 
 */
/**
 * member.js
 */
function join_check(){
   

   if($.trim($("#user_id").val())==""){
      alert("회원아이디를 입력하세요!");
      $("#user_id").val("").focus();
      return false;
   }
   
   // 아이디 중복 찾기 버튼을 눌렀는지 확인
  var idDuplicateChecked = document.getElementById("idDuplicateChecked").value;
 
  // 아이디 중복 찾기 버튼을 누르지 않은 경우
  if (idDuplicateChecked !== "아이디 중복검사") {
    alert("아이디 중복 찾기 버튼을 눌러주세요.");
    return false; // 회원가입을 중단
  }
   
   $user_pwd=$.trim($("#user_pwd").val());
   $user_pwd2=$.trim($("#user_pwd2").val());
   if($user_pwd == ""){
      alert("비밀번호를 입력하세요!");
      $("#user_pwd").val("").focus();
      return false;
   }
   if($user_pwd.length<8) {
      alert("비밀번호는 8자 이상 입력 해야합니다.")
      $("#user_pwd").val("").focus();
      return false;
      
   }
   if($.trim($("#user_pwd2").val())==""){
      alert("비밀번호 확인을 입력하세요!");
      $("#user_pwd2").val("").focus();
      return false;
   }
   if($user_pwd != $user_pwd2){
      alert("비밀번호가 다릅니다!");
      $("#user_pwd").val("");//비번 입력박스를 초기화
      $("#user_pwd2").val("");
      $("#user_pwd").focus();
      return false;
   }
   
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
   if($.trim($("#user_email").val())==""){
      alert("이메일 입력하세요!");
      $("#user_email").val("").focus();
      return false;
   }
   let regexEmail = /^[a-zA-Z][\w]+@[a-zA-Z]+\.(com|net|co\.kr|or\.kr)$/;
    if(!regexEmail.test($("#user_email").val())) {
      alert("이메일 형식으로 입력해주세요!");
      $("#user_email").val("").focus();
      return false;
   } 

      // 이메일인증 버튼을 눌렀는지 확인
  var verifyEmail = document.getElementById("verifyEmail").value;

  // 이메일인증 버튼을 누르지 않은 경우
  if (verifyEmail !== "이메일 인증") {
    alert("이메일인증 버튼을 눌러주세요.");
    return false; // 회원가입을 중단
  }
     // 이메일인증확인 버튼을 눌렀는지 확인
  var verifyEmailConfirm = document.getElementById("verifyEmailConfirm").value;

  // 이메일인증확인 버튼을 누르지 않은 경우
  if (verifyEmailConfirm !== "확인") {
    alert("이메일인증확인 버튼을 눌러주세요.");
    return false; // 회원가입을 중단
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
   
   return true;
}

//중복아이디 검색
//ID Check 
function id_check(){
 /* copy begin */
   $("#idcheck").hide();
   //아이디 영역을 숨김
   $user_id=$.trim($("#user_id").val());
   //1.입력글자 길이 체크
   if($user_id.length < 4){
      $newtext='<font color="red" size="3"><b>아이디는 4자 이상이어야 합니다.</b></font>';
      $("#idcheck").text('');
      //idcheck 아이디 영역 문자열을 초기화
      $("#idcheck").show();
      //idcheck 아이디 영역을 보이게 함.
      $("#idcheck").append($newtext);
      //idcheck영역에 문자열을 추가
      $("#user_id").val('').focus();
      return false;
   };
   if($user_id.length > 12){
      $newtext='<font color="red" size="3"><b>아이디는12자 이하이어야 합니다.</b></font>';
      $("#idcheck").text('');
      //idcheck 아이디 영역 문자열을 초기화
      $("#idcheck").show();
      //idcheck 아이디 영역을 보이게 함.
      $("#idcheck").append($newtext);
      //idcheck영역에 문자열을 추가
      $("#user_id").val('').focus();
      return false;
   };
   //2.입력글자 확인
   if(!(validate_userid($user_id))){
      $newtext='<font color="red" size="3"><b>아이디는 영문소문자,숫자,_조합만 가능합니다.</b></font>';
      $("#idcheck").text('');
      $("#idcheck").show();
      $("#idcheck").append($newtext);
      $("#user_id").val('').focus();
      return false;
   };
   
   //아이디 중복확인
    $.ajax({//$는 jQuery란 뜻. $.ajax 뜻은 jQuery 내의 아작스 실행
        type:"POST",//데이터를 서버로 보내는 방법
       //url:"./member/member_idcheck.jsp",    
        url:"/member_idcheck", //url 패턴 매핑주소 경로
        data: {"id":$user_id},  //좌측 id 피라미터 이름에 우측 $user_id변수값을 저장
        datatype:"int",//서버의 실행된 결과값을 사용자로 받아오는 자료형
        success: function (data) {//success는 아작스로 받아오는것이 성공했을경우
           //서버 데이터를 data변수에 저장
           if(data==1){//중복 아이디가 있다면
            $newtext='<font color="red" size="3"><b>중복 아이디입니다.</b></font>';
            $("#idcheck").text('');
           $("#idcheck").show();
           $("#idcheck").append($newtext);                
             $("#user_id").val('').focus();
             return false;
        
           }else{//중복 아이디가 아니면
            $newtext='<font color="blue" size="3"><b>사용가능한 아이디입니다.</b></font>';
            $("#idcheck").text('');
            $("#idcheck").show();
            $("#idcheck").append($newtext);
            $("#mem_pwd").focus();
           }              
        },
         error:function(){//비동기식 아작스로 서버디비 데이터를
            //못가져와서 에러가 발생했을 때 호출되는 함수이다.
            alert("data error");
         }
      });//$.ajax
 /* end */   
} //end ID Check 

//정규표현식
function validate_userid($user_id)
{
  var pattern= new RegExp(/^[a-z0-9_]+$/);//아이디를 영문소문
  //자와 숫자 와 _조합으로 처리
  return pattern.test($user_id);
};

function validate_useremail($user_email)
{
  var pattern= new RegExp(/^[a-zA-Z][\w]+@[a-zA-Z]+\.(com|net|co\.kr|or\.kr)+$/);//아이디를 영문소문
  //자와 숫자 와 _조합으로 처리
  return pattern.test($user_id);
};






//우편검색 창 (안쓰는 함수같음)
function post_check(){
   $url="zip_find.daum";//매핑주소
   window.open($url,"우편검색","width=515px,height=190px,"
         +"scrollbars=yes");
   //폭이 415 픽셀이고,높이가 190 픽셀,스크롤바가 생성되는
   //우편번호 검색 공지창을 띄운다.
}

//메일 주소 선택과 직접입력
function domain_list(){
  var num=m.mail_list.selectedIndex;//선택한 목록 항목 번호
  if(num == -1){//목록이 선택되지 않았을때 실행
     return true;
  }
  if(m.mail_list.value =="직접입력"){
     m.mail_domain.value = "";
     m.mail_domain.readOnly=false;//쓰기 가능
     m.mail_domain.focus();//입력박스로 포커스 이동
  }else{//목록에서 멜주소를 선택한 경우
    m.mail_domain.value=m.mail_list.options[num].value;
    //목록 옵션 value값이 멜도메인 입력박스로 입력
    m.mail_domain.readOnly=true;//읽기만 가능
  }
}//domain_list()

//member_edit.jsp 유효성 검증
function edit_check(){
   $mem_pwd=$.trim($("#mem_pwd").val());
   $mem_pwd2=$.trim($("#mem_pwd2").val());
   if($mem_pwd == ""){
      alert("비번을 입력하세요!");
      $("#mem_pwd").val("").focus();
      return false;
   }
   if($mem_pwd2 == ""){
      alert("비번확인을 입력하세요!");
      $("#mem_pwd2").val("").focus();
      return false;
   }
   if($mem_pwd != $mem_pwd2){
      alert("비번이 다릅니다!");
      $("#mem_pwd").val("");//비번 입력박스를 초기화
      $("#mem_pwd2").val("");
      $("#mem_pwd").focus();
      return false;
   }
   if($.trim($("#mem_name").val())==""){
      alert("회원이름을 입력하세요!");
      $("#mem_name").val("").focus();
      return false;
   }
   if($.trim($("#mem_zip").val())==""){
      alert("우편번호를 입력하세요!");      
      return false;
   }
   if($.trim($("#mem_zip2").val())==""){
      alert("우편번호를 입력하세요!");      
      return false;
   }
   if($.trim($("#mem_addr").val())==""){
      alert("주소를 입력하세요!");      
      return false;
   }
   if($.trim($("#mem_addr2").val())==""){
      alert("나머지 주소를 입력하세요!");
      $("#mem_addr2").val("").focus();
      return false;
   }
   if($.trim($("#mem_phone02").val())==""){
      alert("폰번호를 입력하세요!");
      $("#mem_phone02").val("").focus();
      return false;
   }
   if($.trim($("#mem_phone03").val())==""){
      alert("폰번호를 입력하세요!");
      $("#mem_phone03").val("").focus();
      return false;
   }
   if($.trim($("#mail_id").val())==""){
      alert("전자우편을 입력하세요!");
      $("#mail_id").val("").focus();
      return false;
   }
   if($.trim($("#mail_domain").val())==""){
      alert("전자우편을 입력하세요!");      
      return false;
   }
}//edit_check()
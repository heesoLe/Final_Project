/**
 * find_id, find_pw
 */
 
 function findid_check(){
 	if($.trim($("#user_name").val())==""){
		alert("회원이름을 입력하세요!");
		$("#user_name").val("").focus();
		return false;
	}
	
	if($.trim($("#user_phone").val())==""){
		alert("휴대전화번호를 입력하세요!");
		$("#user_phone").val("").focus();
		return false;
	}
	//return true;
 }
 
 
 function findpwd_check() {
  if ($.trim($("#user_id").val()) == "") {
    alert("회원아이디를 입력하세요!");
    $("#user_id").val("").focus();
    return false;
  }

  if ($.trim($("#user_name").val()) == "") {
    alert("회원이름을 입력하세요!");
    $("#user_name").val("").focus();
    return false;
  }

  if ($.trim($("#user_email").val()) == "") {
    alert("이메일을 입력하세요!");
    $("#user_email").val("").focus();
    return false;
  }

  var user_id = document.getElementById('user_id').value;
  var user_name = document.getElementById('user_name').value;
  var user_email = document.getElementById('user_email').value;

  // AJAX 요청을 사용하여 Controller로 데이터 전송
  $.ajax({
    type: 'POST',
    url: '/find_pw_ok',
    data: {
      user_id: user_id,
      user_name: user_name,
      user_email: user_email
    },
    success: function(response) {
      if (response == "true") {
        // 일치하는 회원 정보가 있는 경우
        // 비밀번호가 이메일로 전송되었다는 메시지 표시 후 로그인 페이지로 이동
        console.log("아작스 성공");
        alert('비밀번호가 이메일로 전송되었습니다!');
        location.href = '/member_login';
      } else {
        // 일치하는 회원 정보가 없는 경우
        console.log("아작스 실패");
        alert('일치하는 회원이 없습니다!');
      }
    },
    error: function() {
      // AJAX 요청 실패 시 처리할 로직
      alert('AJAX 요청에 실패했습니다!');
    }
  });

  return false; // 폼의 기본 동작인 페이지 이동을 막습니다.
}
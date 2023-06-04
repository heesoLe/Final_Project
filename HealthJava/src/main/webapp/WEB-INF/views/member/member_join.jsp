<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link rel="stylesheet" href="style.css">
<script src="https://code.jquery.com/jquery-3.6.3.js"></script>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<script src="../js/join.js"></script>

<title>HealthJava회원가입</title>

<%-- 우편관련 --%>
<script src="//t1.daumcdn.net/mapjsapi/bundle/postcode/prod/postcode.v2.js"></script>
<script>
    function sample6_execDaumPostcode() {
        new daum.Postcode({
            oncomplete: function(data) {
                // 팝업에서 검색결과 항목을 클릭했을때 실행할 코드를 작성하는 부분.

                // 각 주소의 노출 규칙에 따라 주소를 조합한다.
                // 내려오는 변수가 값이 없는 경우엔 공백('')값을 가지므로, 이를 참고하여 분기 한다.
                var addr = ''; // 주소 변수
                var extraAddr = ''; // 참고항목 변수

                //사용자가 선택한 주소 타입에 따라 해당 주소 값을 가져온다.
                if (data.userSelectedType === 'R') { // 사용자가 도로명 주소를 선택했을 경우
                    addr = data.roadAddress;
                } else { // 사용자가 지번 주소를 선택했을 경우(J)
                    addr = data.jibunAddress;
                }

                // 사용자가 선택한 주소가 도로명 타입일때 참고항목을 조합한다.
                if(data.userSelectedType === 'R'){
                    // 법정동명이 있을 경우 추가한다. (법정리는 제외)
                    // 법정동의 경우 마지막 문자가 "동/로/가"로 끝난다.
                    if(data.bname !== '' && /[동|로|가]$/g.test(data.bname)){
                        extraAddr += data.bname;
                    }
                    // 건물명이 있고, 공동주택일 경우 추가한다.
                    if(data.buildingName !== '' && data.apartment === 'Y'){
                        extraAddr += (extraAddr !== '' ? ', ' + data.buildingName : data.buildingName);
                    }
                    // 표시할 참고항목이 있을 경우, 괄호까지 추가한 최종 문자열을 만든다.
                    if(extraAddr !== ''){
                        extraAddr = ' (' + extraAddr + ')';
                    }
                    // 조합된 참고항목을 해당 필드에 넣는다.
                    document.getElementById("sample6_extraAddress").value = extraAddr;
                
                } else {
                    document.getElementById("sample6_extraAddress").value = '';
                }

                // 우편번호와 주소 정보를 해당 필드에 넣는다.
                document.getElementById('postCode').value = data.zonecode;
                document.getElementById("roadAddr").value = addr;
                // 커서를 상세주소 필드로 이동한다.
                document.getElementById("detailAddr").focus();
            }
        }).open();
    }
</script>
<%-- 우편 끝--%>
<script type="text/javascript">

// 회원가입 페이지에서 이메일 인증 버튼을 누를 때 호출되는 함수
function sendEmailVerification() {
  var userEmail = document.getElementById("user_email").value;

  // AJAX 요청
  $.ajax({
    type: 'POST',
    url: '/emailCertification',
    data: {
      user_email: userEmail
    },
    success: function(response) {
       alert('이메일 전송이 완료되었습니다. 인증해주세요.');
    }
    ,
    error: function() {
      alert('이메일 전송이 실패했습니다. 다시 회원가입해주세요!');
    }
  });
}

// 인증 키 확인 버튼을 눌렀을 때 호출되는 함수
function verifyEmailKey() {
  var userKey = document.getElementById("verification_key").value;

  // AJAX 요청
  $.ajax({
    type: 'POST',
    url: '/verifyEmailKey',
    data: {
      verification_key: userKey
    },
    success: function(response) {
    	alert('인증이 완료되었습니다!');
    }
    ,
    error: function() {
    	alert('인증 키가 올바르지 않습니다. 다시 확인해주세요.');
    }
  });
}
</script>


<style type="text/css">
	/* 폰트 CSS */
	@font-face {
		font-family: 'KIMM_Bold';
		src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2') format('woff2'); /* CDN 절대링크  */
		font-weight: 700;
		font-style: normal;
	}
	/* 되도록 안건드리는 영역 */
	* {
		box-sizing: border-box;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
	}
	html {
		height: 100%;
	}
	body1 {
		margin: 0px;
		height: 100%;
		padding: 0px;
	}
	header {
		width: 100%;
	    position: fixed;
		z-index: 2;
	}
	.wrap {
		margin-top: -110px;
	}
	.main { 
		width: 1400px;
		position : relative;
		top: 105px;
		left: 50%;
        transform: translateX( -50% );
		background-color: rgb(179, 255, 213);  /* 영역 보기 편하라고 배경색 지정함 : 연초록 */
		margin: 0px;
	}
	section {
		height: 100%;
		background-color: rgb(236, 226, 202); /* 영역 보기 편하라고 배경색 지정함 : 연주황 */
	}
	/* 클리어 */
	.clear {
		clear: both;
	}
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
		height: 935px;
	}
	/* 캐러셀 */
	#carouselExampleControls {
		width: 1100px;
		position : relative;
		left: 50%;
        transform: translateX( -50% );
	}
	
	
	
	/* Google web font CDN*/


.signup-form {
	background-color: white;
	border: 2px solid #b21949;
	padding: 20px;
	width: 450px;
	margin: 0 auto;
	margin-top:200px;
	margin-bottom:100px;
	text-align:left;
	border-radius: 5px;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
}

.-form label {
	display: block;
	font-weight: bold;
	margin-bottom: 5px;
	
}


.field select {
	
	width: 190px;
	padding: 5px;
	margin-bottom: 20px;
	border: none;
	border-radius: 5px;
	background-color: #fff;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
	border: 1px solid #dadada;
   
    margin-bottom: 5px;
}

.signup-form input[type="email"] {
	width: 100%;
	padding: 5px;
	margin-bottom: 20px;
	border: none;
	border-radius: 5px;
	background-color: #fff;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
	border: 1px solid #dadada;
   
    margin-bottom: 5px;
}

.signup-form input[type="text"],
.signup-form input[type="password"],
.signup-form input[type="tel"],
.signup-form input[type="number"]
 {
	width: 410px;
	padding: 5px;
	margin-bottom: 20px;
	border: none;
	border-radius: 5px;
	background-color: #fff;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
	border: 1px solid #dadada;
    width: 100%;
    margin-bottom: 5px;
}

.signup-form input[type="button"],
.signup-form input[type="submit"] {
	background-color: #b21949;
	color: #fff;
	border: none;
	padding: 5px 20px;
	border-radius: 5px;
	cursor: pointer;
	border: 1px solid #dadada;
    box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3); 	
    width: 100%;
    margin-bottom: 5px;
}

*{
    box-sizing: border-box; /*�쟾泥댁뿉 諛뺤뒪�궗�씠吏�*/
    outline: none; /*focus �뻽�쓣�븣 �뀒�몢由� �굹�삤寃� */
    font-family: KIMM_Bold;

}

a{
    text-decoration: none;
    color: #222;
}

/*member sign in*/

.member h1{
	text-align: center;
	
}


.member .logo{
    /*濡쒓퀬�뒗 �씠誘몄��씪 �씤�씪�씤 釉붾줉�씠�땲源� 留덉쭊 �삤�넗 �븞�맖 釉붾줉�슂�냼留� �맖 */
    display: block;
    margin :50px auto;
}

.member .field{
    margin :5px 0; /*�긽�븯濡� 醫� �쓣�썙二쇨린*/
}

.member b{
    /* border: 1px solid #000; */
    display: block; /*�닔吏� �젙�젹�븯湲� */
    margin-bottom: 5px;
}

/*input 以� radio �뒗 width 媛� 100%硫� �븞�릺�땲源� */




.member input[type=button],
.member input[type=submit]{
	background-color: #b21949;
	color:#fff;
	box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.3);
}

.member input:focus, .member select:focus{
    border: 1px solid #2db400;
}

.field_id div {
    display: flex;
}

.field_id div input:nth-child(1){
    flex:2;
}

.field_id div input:nth-child(2){
    flex:1;
}

.field.birth div{ /*field �씠硫댁꽌 birth*/
    display: flex;
    gap:10px; /*媛꾧꺽 踰뚮젮以꾨븣 怨듭떇泥섎읆 �궗�슜�븶�굹 */
}

/* .field.birth div > * {  gap �궗�슜�븳嫄곕옉 媛숈� �슚怨쇰�� 以� 
    flex:1;
} */

.field.tel-number div {
    display: flex;
}

.field.tel-number div input:nth-child(1){
    flex:2;
}

.field.tel-number div input:nth-child(2){
    flex:1;
}


.field.address div {
    display: flex;
}

.field.address div input:nth-child(1){
    flex:2;
}

.field.address div input:nth-child(2){
    flex:1;
}
	
</style>
</head>

<body>
<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
			<jsp:include page="../include/header.jsp"/>
		</header>
<div class="member" >
<form name="m" method="post" action="member_join_ok" 
    onsubmit="return join_check();" >
	<input type="hidden"  name="access_token"  id="access_token" value="${access_token}">
	<input type="hidden"  name="user_state"  id="user_state" value="${user_state}">
 	
        <!-- 1. 로고 -->
        <div class="signup-form">
        <h1>회원가입</h1>

        <!-- 2. 필드 -->
        <div class="field_id">
            <b>아이디*</b>
            <div>
            	<input type="text" placeholder="" name="user_id" id="user_id" value="${user_id}">
            	
                <input type="button" value="아이디 중복검사" id="idDuplicateChecked" onclick="id_check();" >
                <script type="text/javascript">
                var idDuplicateChecked = document.getElementById("idDuplicateChecked").value;
                console.log(idDuplicateChecked);
                </script>
                
            </div>
            <div>
            <span id="idcheck"></span>
            </div>
        </div>
        <br>
        <div class="field">
            <b>비밀번호*</b>
            <input class="userpw" type="password" name="user_pwd" id="user_pwd" style="font-family: '맑은 고딕', Arial, sans-serif;">
            <tr>
				<small class="td-infoPs" style="color:#b21949;">*비밀번호는 8자 이상 입력 해야합니다.</small>
			</tr> 
        </div>
        <br>
        <div class="field">
            <b>비밀번호 확인*</b>
            <input class="userpw-confirm" type="password" name="user_pwd2" id="user_pwd2" style="font-family: '맑은 고딕', Arial, sans-serif;" >
            <tr>
				<small class="td-infoPs" style="color:#b21949;">*비밀번호는 8자 이상 입력 해야합니다.</small>
			</tr> 
        </div>
        <br>
        <div class="field">
            <b>이름*</b>
            <input type="text" placeholder="ex) 2자 ~ 4자" name="user_name" id="user_name" value="${user_name}" >
        </div>
		<br>
        <!-- 3. 필드(생년월일) -->
        <div class="field birth" >
            <b>생년월일*</b>
    
                <input type="text" placeholder="ex) 1999년 01월 01일 -> 990101" name="user_birth" id="user_birth"  >                
              
        </div>
        <br>
        <!-- 3. 필드(성별) -->
        <div class="field gender" >
            <b>성별*</b>
    
                <input type="text" placeholder="ex) male/female/남자/여자(대소문자 구분없음)" name="user_gender" id="user_gender" value="${user_gender}">                
              
        </div>
		<br>
        <!-- 4. 필드(주소) -->
        <div class="field address">
            <b>주소*</b>
            
            <div>
                <input type="text" placeholder="우편번호" name="postCode" id="postCode">
                <input type="button" onclick="sample6_execDaumPostcode()" value="우편번호 찾기">
            </div>
       		 	<input type="text" placeholder="주소" name="roadAddr" id="roadAddr">
        	    <input type="text" placeholder="상세주소" name="detailAddr" id="detailAddr">
				<input type="hidden" id="sample6_extraAddress" placeholder="참고항목" value=" ">
        </div>
		<br>
        <!-- 5. 이메일_전화번호 -->
        <div class="field">
            <b>이메일*</b>
            <div>
           		<input type="email" placeholder="ex) abc123@naver.com" name="user_email" id="user_email" value="${user_email}">
		 		<input type="button" value="이메일 인증" id="verifyEmail" onclick="sendEmailVerification();" >
       		</div>
        
       		<div>
            	<input type="text" id="verification_key" name="verification_key" >
            	<input type="button" value="확인" id="verifyEmailConfirm" onclick="verifyEmailKey();" >
        	</div>
        </div>
        <br>
        <div class="field tel-number">
            <b>휴대전화*</b>
            
            <div>
                <input type="tel" placeholder="ex) 01011112222" name="user_phone" id="user_phone">
                
            </div>
            
        </div>

        <!-- 6. 가입하기 버튼 -->
        <input type="submit" value="가입하기">

        
        
    </div>
    </form>
    </div>
	<%-- top버튼 삭제 X --%>
			<div id="topBtn">
				<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
			</div>
	<%-- 푸터 영역 --%>
	<footer>
	
			<%-- header include --%>
			<jsp:include page="../include/footer.jsp"/>
		
	</footer>
	
	</div>
	<script type="text/javascript">
	
		<%-- top버튼 부
		분 --%>
		// 클릭 이벤트 핸들러
		$("#topBtn").click(function(e) {
			e.stopPropagation();
			$("html, body").animate({
				scrollTop : 0
			}, 'fast', 'easeOutCubic');
		});

		// 스크롤 이벤트 핸들러
		$(window).scroll(function() {
			if ($(window).scrollTop() == 0) {
				$("#topBtn").css("opacity", 0); // TOP 버튼 숨기기
			} else {
				$("#topBtn").css("opacity", 1); // TOP 버튼 나타내기
			}
		});
		
	</script>
</body>
</html>
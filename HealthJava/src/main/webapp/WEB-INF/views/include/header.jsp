<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>

<title>HealthJava</title>
<style type="text/css">
/* 폰트 CSS */
@font-face {
   font-family: 'KIMM_Bold';
   src:
      url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2')
      format('woff2');
   font-weight: 700;
   font-style: normal;
}
/* 메인 컨텐츠 부분 */
.wrap {
   width: 100%;
   height: 100%;
   text-align: center;
   position: absolute;
   top: 105px;
   z-index: 1;
}
/* 헤더 박스 부분 */
.headerbox {
   width: 100%;
   height: 105px;
   position: fixed;
   left: 50%;
   transform: translateX(-50%);
   border-bottom: 1px solid lightgray;
   background-color: white;
   z-index: 2;
}
/* 로고 이미지 */
#logoImage {
   position: fixed;
   left: 7.7%;
   top: 7%;
   transform: translateX(-50%);
}
/* 헤더 박스 안의 컨텐츠 */
.menubox {
   width: 1500px;
   height: 140px;
   position: fixed;
   left: 52%;
   transform: translateX(-50%);
}
/* 메뉴바 관련 */
.navbarbox {
   width: 650px;
   height: 85px;
   position: fixed;
   left: 36%;
   top: 19%;
   transform: translateX(-50%);
}

.navbarbox a {
   color: black;
   text-decoration: none;
   font-family: 'KIMM_Bold', sans-serif;
   font-size: larger;
   margin: 0px 28px 0px 28px;
}

.navbarbox a:active {
   color: orange;
}

#a2 {
   margin-left: 30px;
}
/* 드롭박스 관련 */
#dropbtn {
   background-color: white;
   color: black;
   padding: 15px;
   font-family: 'KIMM_Bold', sans-serif;
   font-size: larger;
   border: none;
   margin-left: 12px;
}

#dropbtn:active {
   color: orange;
}

#dropdownbox {
   position: relative;
   display: inline-block;
}

#dropdown-content {
   display: none;
   position: absolute;
   background-color: #f1f1f1;
   min-width: 170px;
   box-shadow: 0px 8px 16px 0px rgba(0, 0, 0, 0.2);
   z-index: 1;
}

#dropdown-content a {
   color: black;
   padding: 12px 16px;
   text-decoration: none;
   display: block;
}

#dropdownbox:hover #dropdown-content {
   display: block;
}
/* 회원가입, 로그인 관련 */
.memberbox {
   width: 196px;
   height: 125px;
   position: fixed;
   right: 5%;
   top: 5%;
}

.memberbox a {
   color: black;
   text-decoration: none;
   font-family: 'KIMM_Bold', sans-serif;
   font-size: small;
}

.memberbox a:hover {
   color: blue;
}
/* 검색창 관련 */
.searchbox {
   position: fixed;
   right: 3%;
   top: 30%;
   transform: translateX(-10%);
}

.searchbox a {
   color: black;
   text-decoration: none;
   font-family: 'KIMM_Bold', sans-serif;
   font-size: 15px;
}

#search {
   width: 330px;
   height: 32px;
   font-size: 15px;
   font-weight: bold;
   border: 0.5px solid lightgrey;
   border-radius: 15px;
   outline: none;
   padding-left: 10px;
   background-color: rgb(240, 239, 239);
   z-index: 2;
}

#searchBtn {
   width: 32px;
   height: 29px;
   position: fixed;
   right: 0;
   top: 5%;
   transform: translateX(-10%);
   border: none;
   border-radius: 15px;
   padding: 0;
}
/* 위로 가기 버튼 관련 */
#topBtn {
   position: fixed;
   bottom: 45px;
   right: 5px;
   width: 60px;
   height: 47px;
   text-align: center;
   font-size: 15px;
   font-weight: bold;
   color: #787f83;
   transition: all 200ms ease-out;
   display: inline-block;
   z-index: 10;
}

#topBtn .icon {
   width: 100%;
   height: 100%;
   color: #787f83;
   cursor: pointer;
}
/* 클리어 */
.clear {
   clear: both;
}
.location {
	position: fixed;
	bottom: -700%;
	right: 0.7%;
}
</style>
</head>
<body>
   <div class="headerbox">
      <div class="menubox">
         <a href="/product/index"> <img
            src="<%=request.getContextPath()%>/images/logo1.png" id="logoImage"
            width="200" height="90" alt="로고 사진">
         </a>

         <div class="navbarbox">

            <div id="dropdownbox">
               <button id="dropbtn" value="소도구">제품</button>
               <div id="dropdown-content">

                  <a href="/product/main">매트</a> <a href="/product/main">짐볼</a>

               </div>
            </div>

            <a id="a2" href="/notice">고객 센터</a> <a id="a3" href="/location">찾아오시는 길</a>
         </div>
         <div class="searchbox">
            <c:set var="session_id" value="${session_id}" />
            <c:set var="session_token" value="${session_token}" />

            <c:choose>
               <c:when test="${not empty session_id && not empty session_token}">
                  <%--카카오회원 일때 --%>
                  <b>${session_id}</b> 님 | <a href="/myPage_Main">마이페이지</a> | <a href="/myPage_like">찜목록</a> | <a href="/myPage_cart">장바구니</a> | <a href="/kakao_logout">로그아웃</a> 
               </c:when>
               
               <c:when test="${session_id eq 'admin' && empty session_token}">
                  <%--관리자일때 --%>
                  <b>${session_id}</b> | <a href="/admin_main">관리자페이지</a> | <a href="/member_logout">로그아웃</a> 
               </c:when>
               
               <c:when test="${not empty session_id && empty session_token}">
                  <%--일반회원 --%>
                  <b>${session_id}</b> | <a href="/myPage_Main">마이페이지</a> | <a href="/myPage_like">찜목록</a> | <a href="/myPage_cart">장바구니</a> | <a href="/member_logout">로그아웃</a>
               </c:when>

               <c:otherwise><%--비회원 --%>
                  <a href="/member_login">로그인</a> | <a href="/member_join">회원가입</a>
               </c:otherwise>
            </c:choose>

         </div>
      </div>
    <!-- 채팅 include(로고 나타나고 클릭 시 채팅으로 넘어가야함) -->
	<div class="location">
		<jsp:include page="../chat/chatting.jsp"/>
	</div>
	
   </div>

   <script type="text/javascript">
        // 클릭 이벤트 핸들러
        $("#topBtn").click(function(e){
            e.stopPropagation();
            $("html, body").animate({scrollTop : 0}, 'fast', 'easeOutCubic');
        });

        // 스크롤 이벤트 핸들러
        $(window).scroll(function(){
            if($(window).scrollTop()==0) {
                $("#topBtn").css("opacity", 0); // TOP 버튼 숨기기
            } else {
                $("#topBtn").css("opacity", 1); // TOP 버튼 나타내기
            }
        });
        
        // 회사소개 클릭시 새창 열기
        function openPopup_company_introduce() {
            var page_width = '800';
            var page_height = '600';
        
            // 팝업을 가운데 위치시키기 위해 아래와 같이 값 구하기
            var page_left = Math.ceil((window.screen.width - page_width)/2);
            var page_top = Math.ceil((window.screen.height - page_height)/2);
    
        window.open("../company_introduce ", "company_introduce",'width='+ page_width +', height='+ page_height +', left=' + page_left + ', top='+ page_top);
        
        }
    </script>
</body>
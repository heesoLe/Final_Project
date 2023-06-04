<%@ page contentType="text/html; charset=UTF-8" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<title>Footer</title>
<link rel="stylesheet" type="text/css" href="./css/footer.css">
<style type="text/css">
	/* 푸터 박스 부분 */
	#footerbox {
		width: 100%;
		height: 200px;
	    font-size: x-small;
	    font-family: 'KIMM_Bold', sans-serif;
	    background-color: rgb(241, 241, 241);
	}
	/* 푸터 박스 안의 틀 */
	#innerbox {
	    width: 1300px;
	    height: 180px;
	    margin: auto;
	}
	/* 푸터 카테고리 관련 */
	#categorybox {
	    height: 30px;
	    float: left;
	    margin: 40px 0px 15px 0px;
	}
	#categorybox ul {
	    padding: 0;
	}
	#categorybox li {
	    list-style: none;
	    list-style-type: none;
	    float: left;
	    margin-right: 30px;
	}
	#categorybox a {
	    font-size: 12.5px;
	    text-decoration: none;
	    color: black;
	}
	/* 푸터 안내글 부분 */
	#infobox {
	    width: 1100px;
	    height: 65px;
	    float: left;
	    text-align: left;
	}
	/* 나이스페이 마크 관련 */
	#checkbox {
	    width: 65px;
	    height: 65px;
	    text-align: center;
	    float: right;
	    margin-right: 30px;
	}
	input#checkIcon {
	    background-image: url(../images/nicepay.png);
	    background-color: transparent;
	    background-repeat: no-repeat;
	    background-position: 0px 0px;
	    border: none;
	    cursor: pointer;
	    width: 55px;
	    height: 64px;
	}
	/* 클리어 */
	.clear {
		clear: both;
	} 
	/* 폰트 CSS */
	@font-face {
	   font-family: 'KIMM_Bold';
	   src:url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2') format('woff2');
	   font-weight: 700;
	   font-style: normal;
	}
	
	/* 메인 컨텐츠 부분 */
	#wrap {
	   width: 100%;
	   height: 100%;
	   text-align: center;
	}
</style>
</head>
<body>
   <!-- footer -->
   <div id="footerbox">
      <div id="innerbox">
            <div id="categorybox">
                <ul>
                    <li><a href="javascript:void(0);" onclick="openPopup_service();">서비스 이용약관</a></li>
                    <li><a href="javascript:void(0);" onclick="openPopup_privacy();">개인정보 처리방침</a></li>
                    <li><a href="javascript:void(0);" onclick="openPopup_inquiry();">입점/제휴 문의</a></li>
                    <li><a href="javascript:void(0);" onclick="openPopup_company_introduce();">회사소개</a></li>
                </ul>
            </div>
            <div id="infobox">
                <br>주식회사 헬스자바 &nbsp;&nbsp; | &nbsp;&nbsp; 대표자명 : 이용현 &nbsp;&nbsp; | &nbsp;&nbsp; 사업자 등록번호 : 120-87-00000 &nbsp;&nbsp; | &nbsp;&nbsp; 통신판매업신고번호 : 제 2023-서울강남-00000호 &nbsp;&nbsp; | &nbsp;&nbsp; 개인정보관리자 : 이용현 leeyoung0919@naver.com &nbsp;&nbsp; | &nbsp;&nbsp; TEL : 1644-0000
                <br>서울특별시 강남구 강남대로84길 16, 11층 &nbsp;&nbsp; | &nbsp;&nbsp; 구매안전(에스크로)서비스
                <br><br>© copyright (c) www.HealthJava.co.kr all rights reserved.
            </div>
            <div id="checkbox">
            <input type="image" id="checkIcon" src="<%=request.getContextPath()%>/images/nicepay.png" onclick="openPopup_certificate()" value="" alt="인증 마크 클릭 이동">
            </div>
        </div>
   </div>
   <!-- footer 끝 -->
   <script type="text/javascript">

      <%-- footer 부분 --%>
      // 서비스 이용약관 텍스트 클릭시 새창 열기
      function openPopup_service() {
           var page_width = '580';
           var page_height = '650';
       
           // 팝업을 가운데 위치시키기 위해 아래와 같이 값 구하기
           var page_left = Math.ceil((window.screen.width - page_width)/2);
           var page_top = Math.ceil((window.screen.height - page_height)/2);
   
       window.open("../service", "service",'width='+ page_width +', height='+ page_height +', left=' + page_left + ', top='+ page_top);
       
       }
       
      // 개인정보 처리 텍스트 클릭시 새창 열기
      function openPopup_privacy() {
           var page_width = '580';
           var page_height = '650';
       
           // 팝업을 가운데 위치시키기 위해 아래와 같이 값 구하기
           var page_left = Math.ceil((window.screen.width - page_width)/2);
           var page_top = Math.ceil((window.screen.height - page_height)/2);
   
       window.open("../privacy", "privacy",'width='+ page_width +', height='+ page_height +', left=' + page_left + ', top='+ page_top);
       
       }
      
      // 입점/제휴 문의 텍스트 클릭시 새창 열기
      function openPopup_inquiry() {
           var page_width = '580';
           var page_height = '555';
       
           // 팝업을 가운데 위치시키기 위해 아래와 같이 값 구하기
           var page_left = Math.ceil((window.screen.width - page_width)/2);
           var page_top = Math.ceil((window.screen.height - page_height)/2);
   
       window.open("../inquiry", "inquiry",'width='+ page_width +', height='+ page_height +', left=' + page_left + ', top='+ page_top);
       
       }
      
      // 인증 마크 클릭시 새창 열기
       function openPopup_certificate() {
           var page_width = '510';
           var page_height = '430';
       
           // 팝업을 가운데 위치시키기 위해 아래와 같이 값 구하기
           var page_left = Math.ceil((window.screen.width - page_width)/2);
           var page_top = Math.ceil((window.screen.height - page_height)/2);
   
       window.open("../certificate", "certificate",'width='+ page_width +', height='+ page_height +', left=' + page_left + ', top='+ page_top);
       
       }
      
      // 회사소개 클릭시 새창 열기
       function openPopup_company_introduce() {
           var page_width = '800';
           var page_height = '600';
       
           // 팝업을 가운데 위치시키기 위해 아래와 같이 값 구하기
           var page_left = Math.ceil((window.screen.width - page_width)/2);
           var page_top = Math.ceil((window.screen.height - page_height)/2);
   
       window.open("../company_introduce", "company_introduce",'width='+ page_width +', height='+ page_height +', left=' + page_left + ', top='+ page_top);
       
       }
   </script>
</body>
</html>
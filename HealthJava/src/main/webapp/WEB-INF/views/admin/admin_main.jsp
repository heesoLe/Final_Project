<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link   href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css"   rel="stylesheet"   integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65"   crossorigin="anonymous"><%-- CDN 절대링크 --%>
<script   src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"   integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN"   crossorigin="anonymous"></script><%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js"   integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM="   crossorigin="anonymous"></script><%-- CDN 절대링크 --%>
<script   src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script><%-- CDN 절대링크 --%>
<script   src="../js/admin_Member.js"></script>
<script   src="../js/admin_CSBoard.js"></script>
<script   src="../js/admin_Product.js"></script>
<script   src="../js/admin_PQNA.js"></script>
<script   src="../js/admin_Order.js"></script>

<title>HealthJava 관리자 회원관리 Page</title>

<style type="text/css">
   /* 폰트 CSS */
   @font-face {
      font-family: 'KIMM_Bold';
      src:
         url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2')
         format('woff2'); /* CDN 절대링크  */
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
   
   body {
      margin: 0px;
      height: 100%;
      padding: 0px;
   }
   
   header {
      width: 100%;
      position: fixed;
      z-index: 2;
   }
   
   footer {
      bottom: 0;
      z-index: 5;
      position: relative;
   }
   
   .wrap {
      margin-top: -110px;
      min-height: 100%;
      position: relative;
   }
   
   .main {
      width: 1400px;
      height: 100%; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 */
      position: relative;
      top: 105px;
      left: 50%;
      transform: translateX(-50%);
      background-color: white; /* 영역 보기 편하라고 배경색 지정함 : 하얀색 */
      margin-bottom: auto;
   }
   
   section {
      height: 1500px; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 */
      /* background-color: rgb(236, 226, 202); 영역 보기 편하라고 배경색 지정함 : 연주황 */
   }
   /* 클리어 */
   .clear {
      clear: both;
   }
   /* 밑의 영역부터 css시작 */
   .container {
      width: 100%;
   }
   
   #btn {
      border-color: #b21949;
      background-color: #b21949;
      color: #fff;
   }
   /* 페이징 처리 */
   /* 페이징 전체 틀 */
   .pagination-container {
      margin: 10px auto;
      display: flex;
      justify-content: center;
   }
   
   .pagination {
      position: relative;
   }
   /* 'PREV' 전체 틀 */
   #pagination a {
      position: relative;
      display: inline-block;
      color: #b21949; /* 글자색상 */
      text-decoration: none;
      font-size: 1.2rem;
      padding: 8px 16px 10px;
   }
   /* 'PREV' 부분 */
   #pagination a:before {
      z-index: -1;
      position: absolute;
      height: 100%;
      width: 100%;
      content: "";
      top: 0;
      left: 0;
      background-color: #FC5400;
      border-radius: 24px;
      -webkit-transform: scale(0);
      transform: scale(0);
      transition: all 0.2s;
   }
   
   #pagination a:hover, #pagination a #pagination-active {
      color: #fff;
   }
   
   #pagination a:hover:before, #pagination a #pagination-active:before {
      -webkit-transform: scale(1);
      transform: scale(1);
      background-color: #FC5400;
   }
   
   #pagination #pagination-active {
      color: #fff;
      background-color: #FC5400;
   }
   
   #pagination #pagination-active:before {
      -webkit-transform: scale(1);
      transform: scale(1);
   }
   /*'NEXT' 전체 틀 */
   #pagination-newer {
      margin-right: 50px;
      width: 200px;
   }
   
   #pagination-older {
      margin-left: 50px;
   }
   
   .boardList tr {
      border-bottom: 1px solid #b21949;
   }
   
   tbody, td, tfoot, th, thead, tr {
    border-color: inherit;
    border-style: solid;
    border-width: 0;
    padding-top: 10px;
   padding-bottom: 10px;
   padding-left: 10px;

}
/* 회원관리 게시판 전체 틀 */ 
   .list {
      width: 1400px;
      height: 80px;
      padding-top: 50px;
      padding-left: 50px;
      padding-right: 100px;
      font-family: 'KIMM_Bold';
      }
      
         #btn2{
      border-color: #b21949; 
      background-color: #b21949; 
      color: #fff;
   }
      .memList{
      width: 1250px;   
       border-top: 3px solid #b21949;
       border-bottom: 3px solid #b21949;
       font-family: 'KIMM_Bold';   
   }
   .memList th {
      width: 250px;
   }
   .memList td {
      font-family: 'KIMM_Bold';
      line-height: 3;
      padding-top: 20px;
      padding-bottom: 0px;
   }
   
   th.th-list {
       /*border-bottom: 2px solid #f5ad56;*/
       font-family: 'KIMM_Bold';
       padding-top: 20px;
      padding-bottom: 20px;
   }
   
   td.td-inputInfo {
    text-align: left;
}
   td.td-infoPs {
    text-align: left;
}
   .meau a {
      color: white;
      text-decoration: none;
   }
   
   .boardList a {
      text-decoration: none;
   }
   select {
      padding : 5px 5px;
   }
   
/* adminMemList.jsp UI : 회원 관리 */
/* 회원관리 게시판 전체 틀 */
.list {
   width: 1400px;
   height: 80px;
   padding-top: 30px;
   padding-left: 50px;
   padding-right: 100px;
   font-family: 'KIMM_Bold';
}
/* 게시판 테두리 */
.boardList {
   border: none;
   border-top: 3px solid #b21949;
   border-bottom: 3px solid #b21949;
   font-family: 'KIMM_Bold';
}
.boardList th {
   border-bottom: 3px solid #b21949;
    padding-top: 20px;
   padding-bottom: 20px;
}

.boardList td {
    padding-top: 20px;
   padding-bottom: 20px;
}


/* admin계정 UI */

/* 관리자 메인이미지  */
.adminMainpage {

   width: 1400px;
   height: 300px;
   position: relative;
   left: 50%;
   transform: translateX(-50%);
   
}

img, svg {
    margin-left: 50px;
    margin-top: 10px;
    vertical-align: middle;
}

.profile_img {
   width: 1400px;
   height: 200px;
   margin-top:20px;
   padding-left: 50px;
   padding-right: 100px;
   background-color: #b21949;
}

/*Admin Page 지정*/
.name {
   padding-top: 30px;
   padding-left: 10px;
   padding-right: 1000px;
   font-family: 'KIMM_Bold';
}

.myinfo {
   padding-left: 170px;
   padding-right: 100px;
   font-family: 'KIMM_Bold';
   color: white;
}

.myinfo_date {
   padding-left: 170px;
   padding-right: 100px;
   font-family: 'KIMM_Bold';
   color: white;
}

.meau {
   padding-top: 30px;
   margin-left: 800px;
   font-family: 'KIMM_Bold';
   width:3000px;
   height:300px;
   }
}

.meau a {
   color: white;
   text-decoration: none;
}

ul {
   list-style: none;
}

li {
   float: left;
}

.inquire-table-div{
   width: 90%;
     max-width: 700px;
     padding: 40px 20px;
     border: 2px solid #b21949;
     border-radius: 16px;
     margin: 20px auto;
     font-family: 'KIMM_Bold';
}
#adminTab6:hover{
	color: white;
}
</style>
<script>
$(document).ready(function(){
   Member_List();
});
</script>

</head>
<body>
   <%-- 전체 영역 --%>
   <div class="wrap">
   <%-- 헤더 영역 --%>
   <header><%-- header include --%>
      <jsp:include page="../include/header.jsp" />
   </header>
   <%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>
   <section>
      <div class="main">
      
      <div class="adminMainpage">   <%-- adminMainpage --%>
         <%-- admin 계정 --%>
         <h1 class="name" style="color: #b21949">Admin Page</h1>
         <div class="profile_img" align="center">
         <%-- 이미지 클릭시 관리자 메인화면으로 이동 --%>
         <a href="admin_main"><img width="150px" height="190px" align="left" alt="adminImage" src="<%=request.getContextPath()%>/images/admin.png"> </a>

            <div class="meau" style="color: white;">
            <ul>
               <li id="adminTab1" style="cursor:pointer;" value="회원관리" onclick="Member_List();">회원 관리  |&nbsp;</li>
               <li id="adminTab2" style="cursor:pointer;" value="문의게시판" onclick="CSBoard_search();">문의 게시판 |&nbsp;</li> 
               <li id="adminTab3" style="cursor:pointer;" value="상품목록" onclick="product_search();">상품 목록 |&nbsp;</li> 
               <li id="adminTab4" style="cursor:pointer;" value="상품QNA" onclick="GsQNA_search();">상품 QNA |&nbsp;</li>
               <li id="adminTab5" style="cursor:pointer;" value="주문내역" onclick="Order_search();">주문내역 |&nbsp;</li> 
               <li><a href="/chat/rooms" id="adminTab6" style="cursor:pointer;" target="_blank">채팅 관리 &nbsp;</a></li> 
               </ul>  
             </div>

<script type="text/javascript">

</script>
         </div> <%-- end profile_img : 이미지 div --%>
         </div> <%-- end adminMainpage : 관리자 계정 고정 --%>

         <%-- 전체 틀 회원관리 테이블 --%>
         <div class="list">
            <div id="ajaxHead">
            
            </div>
            <div id="ajaxhome">
            
            </div>
            <table class="boardList" width="1300px;">
            <thead id="ajaxTh">
            
            </thead>
            


            <tbody id="ajaxTable">
            
            </tbody>
            </table>            

      
            
            <%--회원 관리 게시판 끝 --%>
            <%-- 회원 체크(블랙리스트) 버튼 --%>
            <p><p>
            
            <p>


         </div> <%-- 회원 테이블 끝 --%>

      </div>
      <%-- top버튼 삭제 X --%>
      <div id="topBtn">
         <span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
      </div>
   </section>
   
   <%-- 푸터 영역 --%>
   <footer>
      <!-- footer -->
      <jsp:include page="../include/footer.jsp" />
      <!-- footer 끝 -->
   </footer>
   <script type="text/javascript">
      
   <%-- top버튼 부분 --%>
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
      
	// 채팅 관리 팝업 열기
		function Chat_search() {
	window.open("/chat/rooms", "chatroom", 'top=245, left=1290, width=380, height=680, scrollbars=no, toolbar=no, location=no, resizable=no, status=no, menubar=no');
	}
   </script>
   </div> <%-- end wrap --%>

</body>
</html>
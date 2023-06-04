<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="../include/header.jsp"/>

<script type="text/javascript" src="<%=request.getContextPath()%>/js/jquery.js"></script>
<script src="../js/cs.js"></script>
<style>
@charset "UTF-8";

#cs_faq_list {
	list-style: none;
	position: relative;
	padding: 0px 0px 0px 10%;
	font-family: 'KIMM_Bold';
	color: #b21949;
}

#cs_faq_list li {
	display: inline;
	padding: 10px 10px;
}

#cs_faq_list li a {
	color: inherit;
	text-decoration: none;
	font-size: 25px;
	font-family: 'KIMM_Bold';
}

#label {
	list-style: none;
	position: relative;
	padding: 0px 0px 0px 10%;
	font-family: 'KIMM_Bold';
}

#inquire_notice_list {
	display: inline;
}

#label li {
	display: inline;
	padding: 10px 10px;
	color: gray;
	font-size: 15px;
}

#cs_faq_list li a:hover {
	text-decoration: none;
	color: black;
	cursor: pointer;
}

table {
	border-collapse: collapse;
	border-spacing: 0;
}

div .select {
	padding: 80px 0;
}

section.notice {
	padding: 120px 0px 20px 0px;
}

/* .page-title {
  margin-bottom: 60px;
}
.page-title h3 {
  font-size: 28px;
  color: #333333;
  font-weight: 400;
  text-align: center;
} */

/*  
.board-table tbody .hidden {
  선택된 행에 스타일 적용
  display: none;
}
 */
#board-search {
	margin: auto;
}

#board-search .search-window {
	padding: 15px 0;
	background-color: #b21949;
}

#board-search .search-window .search-wrap {
	position: relative;
	/*   padding-right: 124px; */
	margin: 0 auto;
	width: 80%;
	max-width: 564px;
}

#board-search .search-window .search-wrap input {
	height: 40px;
	width: 100%;
	font-size: 14px;
	padding: 7px 14px;
	border: 1px solid #ccc;
	font-family: 'KIMM_Bold';
}

#board-search .search-window .search-wrap input:focus {
	border-color: #333;
	outline: 0;
	border-width: 1px;
}

#board-search .search-window .search-wrap .btn {
	position: absolute;
	right: 0;
	top: 0;
	bottom: 0;
	width: 108px;
	padding: 0;
	font-size: 16px;
	font-family: 'KIMM_Bold';
	color: white;
	background: #b21949;
}

.board-table {
	font-size: 13px;
	width: 100%;
	border-top: 1px solid #ccc;
	border-bottom: 1px solid #ccc;
	font-family: 'KIMM_Bold';
}

.board-table a {
	color: #333;
	display: inline-block;
	line-height: 1.4;
	word-break: break-all;
	vertical-align: middle;
	text-decoration: none;
}

.board-table a:hover {
	text-decoration: underline;
}

.board-table th {
	text-align: center;
}

.board-table .th-num {
	width: 100px;
	text-align: center;
	font-size: 15px;
	background-color: #b21949;
}

.board-table .th-title {
	background-color: #b21949;
	font-size: 15px;
}

.board-table .th-date {
	background-color: #b21949;
	width: 200px;
	font-size: 15px;
}

.board-table .th-name {
	background-color: #b21949;
	width: 200px;
	font-size: 15px;
}

.board-table th, .board-table td {
	padding: 14px 0;
}

.board-table tbody td {
	border-top: 1px solid #e7e7e7;
	text-align: center;
	font-size: larger;
    color: #b21949;
}

.board-table tbody th {
	padding-left: 28px;
	padding-right: 14px;
	border-top: 1px solid #e7e7e7;
	text-align: center;
}

.board-table tbody th p {
	display: none;
}

.board-table tbody tr.hidden {
	display: none;
}

.board-table tbody tr:nth-child(even) {
	background-color: #b21949;
}

.btn {
	display: inline-block;
	padding: 0 30px;
	font-size: 15px;
	font-weight: 400;
	background: transparent;
	text-align: center;
	white-space: nowrap;
	vertical-align: middle;
	-ms-touch-action: manipulation;
	touch-action: manipulation;
	cursor: pointer;
	-webkit-user-select: none;
	-moz-user-select: none;
	-ms-user-select: none;
	user-select: none;
	border: 1px solid transparent;
	text-transform: uppercase;
	-webkit-border-radius: 0;
	-moz-border-radius: 0;
	border-radius: 0;
	-webkit-transition: all 0.3s;
	-moz-transition: all 0.3s;
	-ms-transition: all 0.3s;
	-o-transition: all 0.3s;
	transition: all 0.3s;
}

.btn-dark {
	background: #555;
	color: #fff;
}

.btn-dark:hover, .btn-dark:focus {
	background: #373737;
	border-color: #373737;
	color: #fff;
}

.btn-dark {
	background: #555;
	color: #fff;
}

.btn-dark:hover, .btn-dark:focus {
	background: #373737;
	border-color: #373737;
	color: #fff;
}

.btn_contact {
	height: 80px;
	width: 100%;
	margin: auto;
	padding: 30px 0px 20px 0px;
	display: inline-block;
	font-size: 15px;
	font-weight: 400;
	background: transparent;
	text-align: center;
	white-space: nowrap;
}

.btn_1 {
	height: 40px;
	width: 100px;
	background: #b21949;
	color: #fff;
	font-family: 'KIMM_Bold';
}

.btn_1:hover, .btn_1:focus {
	background: #b21949;
	border-color: #b21949;
	color: #fff;
}

.btn_1 {
	background: #b21949;
	color: #fff;
}

.btn_1:hover, .btn_1:focus {
	background: #b21949;
	border-color: #b21949;
	color: #fff;
}

/* reset */
* {
	list-style: none;
	text-decoration: none;
	padding: 0;
	margin: 0;
	box-sizing: border-box;
}

.clearfix:after {
	content: '';
	display: block;
	clear: both;
}

.container {
	width: 1100px;
	margin: 0 auto;
}

.blind {
	position: absolute;
	overflow: hidden;
	clip: rect(0, 0, 0, 0);
	margin: -1px;
	width: 1px;
	height: 1px;
}

#label_hr {
	border: 0;
	height: 4px; /* hr 높이 설정 */
	background-color: #b21949; /* hr 색상 설정 */
	margin: 10px 0px; /* hr 위아래 간격 설정 */
}

p {
	font-size: medium;
	background-color: white;
}
#faq_category{
	border: none; 
	background: transparent;
	text-align: center;
	outline: none;
}



</style>

<script>
	function check(){
		alert("ccc");
	}
</script>

<section class="notice" style="margin-bottom: 150px;">

<div style="margin-top: 10px;">
 <ul id="cs_faq_list">
  <li><a href="notice">공지사항</a></li>
  <li><a href="FAQ">자주 묻는 질문</a></li>
  <li><a href="contact">1:1문의</a></li>
 </ul>
 <hr id="label_hr">
</div>
    
<div>

 <ul id="label">
  <li><a href = "FAQ"><input type="text" value="전체" id="faq_category"  name="faq_category" size="10" style="cursor: pointer;" readonly /></a></li>
  <li><a href = "FAQ?faq_category=로그인/정보"><input type="text" value="로그인/정보" id="faq_category" name="faq_category" size="10" style="cursor: pointer;" readonly /></a></li>
  <li><a href = "FAQ?faq_category=주문/결제"><input type="text" value="주문/결제" id="faq_category" size="8" name="faq_category" style="cursor: pointer;" readonly /></a></li>
  <li><a href = "FAQ?faq_category=배송문의"><input type="text" value="배송문의" id="faq_category" size="8" name="faq_category" style="cursor: pointer;" readonly /></a></li>
  <li><a href = "FAQ?faq_category=교환/취소(반품)"><input type="text" value="교환/취소(반품)" id="faq_category" name="faq_category" size="12" style="cursor: pointer;" readonly /></a></li>
 </ul>
</div>
<br>

   
  <!-- board list area -->
    <div id="board-list">
        <div class="container">
            <table class="board-table" id="cs_list">
                <thead>
                <tr>
                    <th scope="col" class="th-num" style="color:white;">구분</th>
                    <th scope="col" class="th-title" style="color:white;">제목</th>
                    <!-- <th scope="col" class="th-date">등록일</th> -->
                </tr>
                <tr></tr>
                </thead>
                <tbody>
                <c:if test="${!empty clist }"> <%-- 검색 전후 목록이 있는 경우 실행 --%>
				<c:forEach var="c" items="${clist }">
				<tr onclick="toggleContent(this)">
                    <td width="150px;">${c.faq_category }</td>
                    <th><a href="#">${c.faq_title }</a></th>
               	</tr>
                <tr class="hidden">
                	<td style="background-color:#f1f1f1; color:#b21949;"></td>
                	<td style="background-color:#f1f1f1; color:#b21949;">${c.faq_cont}</td>
                </tr>
				</c:forEach>
						</c:if > 
						
						<%-- 작성글이 있을경우 --%>
						<c:if test="${empty clist }">
						<tr>
						<td colspan="2">작성 글이 없습니다.</td>
						</tr>
						</c:if>
						<!-- 
                <tr onclick="toggleContent(this)">
                    <td>배송문의</td>
                    <th><a href="#" >배송지를 잘못 입력했어요. 어떻게 해야 할까요?</a></th>
                    
                </tr>
                <tr class="hidden">
                	<td></td>
                	<td>배송지를 잘못 입력했으면...어쩌라고</td>
                </tr>
                <tr onclick="toggleContent(this)">
                    <td>상품문의</td>
                    <th><a href="#">재고가 없어요. 언제쯤 입고 될까요?</a></th>
                   
                </tr>
                <tr class="hidden">
                	<td></td>
                	<td>배송지를 잘못 입력했으면...어쩌라고</td>
                </tr>
                <tr onclick="toggleContent(this)">
                    <td>상품문의</td>
                    <th><a href="#">구매했을때 보다 가격이 떨어졌어요. 차액 환불 되나요?</a></th>
                    
                </tr>
                <tr class="hidden">
                	<td></td>
                	<td>배송지를 잘못 입력했으면...어쩌라고</td>
                </tr>

                <tr onclick="toggleContent(this)">
                    <td>로그인/정보</td>
                    <th><a href="#">개인정보 수정은 어디서 하나요?</a></th>
                   
                </tr>
                <tr class="hidden">
                	<td></td>
                	<td>배송지를 잘못 입력했으면...어쩌라고</td>
                </tr>

                <tr onclick="toggleContent(this)">
                    <td>로그인/정보</td>
                    <th><a href="#">아이디와 비번이 기억나지 않아요.</a></th>
                    
                </tr>
                <tr class="hidden">
                	<td></td>
                	<td>배송지를 잘못 입력했으면...어쩌라고</td>
                </tr> -->
                </tbody>
            </table>
        </div>
    </div>
    
     <c:if test="${session_id=='admin' }">
<div class="btn_contact">
 <form action="">
   <button type="button" class="btn_1" onclick="location='FAQ_write';">FAQ 추가</button>
 </form>
</div>
</c:if>
</section>


		<%-- 푸터 영역 --%>
			<footer>
	<!-- footer -->
	<jsp:include page="../include/footer.jsp"/>
	</footer>
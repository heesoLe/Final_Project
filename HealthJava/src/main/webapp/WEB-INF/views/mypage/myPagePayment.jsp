<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<script defer src="<%=request.getContextPath()%>/js/post.js"></script>
<script src="//t1.daumcdn.net/mapjsapi/bundle/postcode/prod/postcode.v2.js"></script>
<script src="<%=request.getContextPath()%>/js/updateInfo.js"></script>
<script src="<%=request.getContextPath()%>/js/post2.js"></script>
<script	src="../js/mypage.js"></script>
<!--<script>Kakao.init('31d2f9dc79f327146c781ff55e8f8b76');</script> -->
<script type="text/javascript" src="https://code.jquery.com/jquery-1.12.4.min.js" ></script>
<script type="text/javascript" src="https://cdn.iamport.kr/js/iamport.payment-1.2.0.js"></script>
    
<script>
	$(document).ready(function(){
		myPagePayment_addr();
	});
</script>

<title>HealthJava 마이페이지</title>


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
		font-family: 'KIMM_Bold', sans-serif;
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
		width: 1600px;
		height: 1200px;
		position: relative;
		top: 105px;
		left: 50%;
		transform: translateX(-50%);
	}
	
	section {
		height: 1200px;
	}
	/* 클리어 */
	.clear {
		clear: both;
	}
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
	}
	
	/*MyPage CSS*/
	table {
		border-collapse: collapse;
		border-spacing: 0;
	}
	section.notice {
		padding: 20px 0;
		/*추가*/
		width: 1000px;
		min-height: 200px;
		margin: 2px;
	}
	
	.aside_left {
		margin-top: 45px;
		margin-left: 60px;
		width: 180px;
		min-height: 700px;
		float: left;
		text-align: left;
	}
	
	.aside_left nav {
		min-height: 600px;
		margin-bottom: 50px;
	}
	
	.aside_left li {
		padding-top: 8.2px;
		padding-bottom: 2px;
		list-style: none;
	}
	
	li{
		padding-top: 10px;
	}
	
	nav {
		min-height: 600px;
		margin-bottom: 50px;
	}
	
	#subspan {
		color: #808080;
	}
	
	div.page-title {
		width: 1000px;
		min-height: 10px;
		padding: 0px 10px;
		text-align: left;
	}
	
	h3.page-title {
		font-size: 25px;
		color: black;
		font-weight: 400;
		text-align: left;
	}
	
	.memBasicInfo {
		height: 120px;
		padding: 20px;
		float: left;
	}
	
	#board-search .search-window {
		width: 1000px;
		min-height: 80px;
		padding: 15px 0;
		text-align: left;
	}
	
	.board-table {
		font-size: 13px;
		width: 100%;
		border-top: 1px solid #ccc;
		border-bottom: 1px solid #ccc;
	}
	
	.board-table th {
		text-align: center;
		border-top-style: solid;
		border-top-color: black;
		border-top-width: 2px;
	}
	
	.board-table .th-num {
		width: 100px;
		text-align: center;
	}
	
	table th.th-title {
		font-size: 15px;
		width: 200px;
	}
	
	table td.td-title {
		font-size: 13px;
	}
	
	table th.th-date {
		font-size: 15px;
		width: 80px;
	}
	
	table th.th-date1 {
		font-size: 15px;
		width: 50px;
	}
	
	table th.th-date2 {
		font-size: 15px;
		width: 150px;
	}
	
	.board-table .th-inputInfo {
		
	}
	
	.board-table th, .board-table td {
		padding-top: 14px;
		padding-bottom: 14px;
	}
	
	.board-table tbody td {
		border-top: 1px solid #e7e7e7;
		text-align: center;
		font-size: 15px;
	}
	
	.board-table tbody th {
		font-size: 15px;
		border-top: 1px solid #e7e7e7;
		text-align: center;
	}
	
	.board-table thead th {
		text-align: center;
	}
	
	.board-table tbody th p {
		display: none;
	}
	
	.th-list{
	    text-align: center;
	    margin-top: 20px;
	    margin-bottom: 20px;
	    padding: 10px;
	    background-color: #b21949;
	    border-bottom-color: white;
	    border-bottom-width: 0.2px;
	    border-bottom-style: solid;
	    color: white;
	}
	
	.td-inputInfo{
		text-align:left;
		padding-left: 20px;
		padding-top: 20px;
	}
	
	.td-infoPs{
		text-align : left;
		padding-left: 20px;
		padding-top: 5px;
		padding-bottom: 15px;
		border-bottom-color: gray;
		border-bottom-width: 0.2px;
		border-bottom-style: solid;
		font-size: 12px; 
		font-weight: bold;
		color: red; 
	}
	
	div.submitBtn{
		float: left;
		margin-left: 100px;
	}
	
	/* 수정 버튼 */
	#updateBtn{
	    padding: 20px 120px;
	    background-color: #b21949;
	    border: 2px solid #b21949;
	    font-size: 20px;
	    font-weight: bold;
	    color: white;
	}	
	
	#resetBtn{
	    padding: 20px 120px;
	    background-color: white;
	    border: 2px solid #b21949;
	    font-size: 20px;
	    font-weight: bold;
	    color: #b21949;
	}
	
	#withdrawalBtn{
		padding: 20px 100px; 
		background-color: #FC5400; 
		border: 1px solid white; 
		color: white; 
		font-size: 20px; 
		font-weight: bold
	}
	
	#changePwdBtn{
		padding: 20px 120px; 
		background-color: #FC5400; 
		border: 1px solid white; 
		color: white; 
		font-size: 20px; 
		font-weight: bold
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
	
	div.myPageTitle {
		width: 1100px;
		margin: 0 auto;
		border: 1px solid red;
	}
	
	div.container {
		width: 1000px;
		margin: 20px 0px;
		/*border: 1px solid red;*/
	}
	
	.innerWrap {
		width: 1000px;
		min-height: 700px;
		padding: 20px;
		float: left;
		margin-top: 10px;
		margin-left: 100px;
	}
	
	.blind {
		position: absolute;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		margin: -1px;
		width: 1px;
		height: 1px;
	}
	
	.clear {
		clear: both; /*float 속성을 제거함으로써 잘못 된 ui 적용을 막아줌 */
	}
	
	/* a 링크 : 메뉴바 */	
	a:link.liList {
		text-decoration: none;
		color: #a399a2;
	}
	
	a:visited.liList {
		text-decoration: none;
		color: #a399a2;
	}
	
	a:hover.liList{
		text-decoration: underline;
		color: #B21948;
	}
	
	a:active.liList {
		text-decoration: none;
		color: #B21948;
	}
	
	table a:link.orderList {
		text-decoration: none; 
		color: black;
	}
	
	table a:visited.orderList {
		text-decoration: none;
		color: black;
	}
	
	table a:hover.orderList{
		text-decoration: underline;
		color: #FC5400;
		cursor: pointer;
	}
	
	table a:active.orderList {
		text-decoration: none;
		color: #FC5400;
	}
	
	/* '기본정보' '*필수사항' 중간 여백  */
	.indent {
		margin-left: 749px;
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
      <%-- 메뉴바 --%>
		<section>
			<div class="main">
				<%-- main 화면 상단 캐러셀 (캐러셀 필요 없는 페이지는 삭제 바람!)--%>
				<aside class="aside_left">
					<nav>
						<ul>
							<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"><a href="myPage_Main" style="text-decoration: none; color: black;">나의 쇼핑</a></li>
							<li><a href="myPage_order" class="liList">주문ㆍ배송</a></li>
							<li><a href="myPage_like" class="liList">찜 목록</a></li>
							<li><a href="myPage_cart" class="liList">장바구니</a></li>
							<li><a href="myPage_review" class="liList">나의 상품후기</a></li>

							<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 회원 정보</li>
							<li><a href="myPage_updateInfo" class="liList" style="color: #B21948;">회원정보 변경</a></li>
							<li><a href="myPage_changePwd" class="liList">비밀번호 변경</a></li>
							<li><a href="myPage_user_Withdrawal" class="liList">회원탈퇴</a></li>
							<li style="margin-bottom: 30px;"><a href="myPage_updateAddress" class="liList">배송지 관리</a></li>
							
						</ul>
					</nav>
				</aside>
		<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>
		<div class="innerWrap">
		<section class="notice">
			<!-- board list area -->
			<div class="page-title">
			<b style="text-align: left; font-size: 20px; margin-left:40px;">주문/결제</b>
				<b class="indent" style="font-size: 13px;">* 필수 입력사항</b>
			</div>
			<br>
			<c:forEach var='i' items='${list}'>
			<c:set var="totalcount" value="${totalcount+i.cart_cnt }"/>
			<c:set var="totalprice" value="${totalprice+i.product_price*i.cart_cnt }" />
			<c:set var="itemcount" value="${itemcount+1 }"></c:set>
			</c:forEach>
			<div class="page-title" style="margin-left: 50px;">
			<form method="post" action="order_insert_ok" id="frm">
			<input type="hidden" name="order_cnt" value="${totalcount }">
			<c:forEach var='i' items='${list}' varStatus="status">
			<input type="hidden" name="order_detail_pno${status.count }" value="${i.cart_pro_no }">
			<input type="hidden" name="order_detail_cnt${status.count }" value="${i.cart_cnt }">
			</c:forEach>
				<table>
					<!--아이디 -->
					<tr>
						<th rowspan="2" class="th-list" width="170px" style="border-top-color: black; border-top-style: solid; border-top-width: 3px;">
							상품명</th>
						<td class="td-inputInfo" style="border-top-color: black; border-top-style: solid; border-top-width: 3px;">
							<input type="text" name="order_product_title" id="order_product_title" 
							value="<c:forEach var='i' items='${list}' begin ='0' end ='0'>${i.product_title} </c:forEach> <c:if test='${itemcount!=1 }'>외 ${itemcount-1}건</c:if>" size="70" style="background-color: #ECECEC;" readonly/>
						</td>
						
						
					</tr>

					<tr>
						<td class="td-infoPs"></td>
					</tr>

					<!--이름-->
					<tr>
						<th rowspan="2" class="th-list">수령인*</th>
						<td class="td-inputInfo"><input type="text" name="user_name" id="user_name" value="${em.user_name}" size="70" placeholder="예)홍길동"></td>
					</tr>
										
					<tr>
						<td class="td-infoPs">* 한글로 2~4자내로 입력</td>
					</tr>
			
					
					<!--주소-->
					<tr>
						<th rowspan="5" class="th-list">배송지 *</th>
						<td class="td-inputInfo">
							
							<input type="radio" id="addr_no" name="addr_no" value="addr_name" checked="checked">기본 주소지
							<c:if test="${!empty alist }">
							<c:forEach var="a" items="${alist}">
							&nbsp;&nbsp;
							<input type='radio' id="addr_no" name='addr_no' value='${a.addr_no}' onclick="myPagePayment_addr();">${a.addr_name}
							</c:forEach>
							</c:if>
						</td>
						
					</tr>
					
				
					<tr>
					
					<td class="td-inputInfo"><input type="text" name="postCode" id="postCode" value="${em.postCode}" size="20" placeholder="우편번호"/>&nbsp;&nbsp;
					<input type="button" value="주소검색" onclick="post()" style="font-weight: bold; padding: 2px;"/>
					</td>
				</tr>

				<tr>
					<td class="td-inputInfo"><input type="text" name="roadAddr" id="roadAddr" value="${em.roadAddr}"	size="70" placeholder="주소"></td>
				</tr>

				<tr>
					<td class="td-inputInfo"><input type="text" name="detailAddr" id="detailAddr" value="${em.detailAddr}" size="70" placeholder="상세주소"></td>
				</tr>
				
				<tr>
					<td class="td-infoPs"></td>
				</tr>
														
					<!--이메일-->
					<tr>
						<th class="th-list" rowspan="2" >이메일 *</th>
						<td class="td-inputInfo"><input type="email" name="user_email" id="user_email" value="${em.user_email}"size="70" placeholder="예) abcdefg11@naver.com"></td>
					</tr>
					
					<tr>
						<td class="td-infoPs"></td>
					</tr>
					
					<!--휴대전화-->
					<tr>
						<th rowspan="2" class="th-list">휴대전화 *</th>
						<td class="td-inputInfo">
								<input type="text" name="user_phone" id="user_phone" size="70" value="${em.user_phone}" placeholder="예)010-1234-5678 -> 01012345678">
						</td>
					</tr>
					
					<tr>
						<td class="td-infoPs"></td>
					</tr>
					
					<!--생년월일-->
					<tr>
						<th rowspan="2" class="th-list" >
						결제 금액</th>
						<td class="td-inputInfo">
								<input type="text" name="order_total" id="user_birth" 
								value="${totalprice }" size="70" readonly />
						</td>
					
					<tr>
						<td class="td-infoPs"></td>
					</tr>
					
					<!--성별-->
					<tr>
						<th rowspan="2" class="th-list" >
						결제 수단</th>
						<td class="td-inputInfo">
								<select name="payment" id="payment" >
									<option value="card">카드 결제</option>
									<option value="cash">무통장 입금</option>
									<option value="kakao">카카오 결제</option>
								</select>
						</td>
					
					<tr>
						<td class="td-infoPs"></td>
					</tr>
					
				</table>
				
			<br><br>
				
				<div class="submitBtn" style="margin-left: 200px;">
				<input id="updateBtn" type="button" value="결제하기" onclick="requestPay()">
				
				<input id="resetBtn" type="reset" value="취소">
				</div>
				</form>

			</div>
			</section>		
			</div>
			</div>
			<%-- top버튼 삭제 X --%>
	         <div id="topBtn">
	            <span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
	         </div>
         
		</section>
		
		<div class="clear"></div>
		
		<%-- 푸터 영역 --%>
		<footer>
			<!-- footer -->
			<jsp:include page="../include/footer.jsp"/>
			<!-- footer 끝 -->
		</footer>
	</div>
	<script>
        var IMP = window.IMP; 
        IMP.init("imp12337201"); 
      
        var today = new Date();   
        var hours = today.getHours(); // 시
        var minutes = today.getMinutes();  // 분
        var seconds = today.getSeconds();  // 초
        var milliseconds = today.getMilliseconds();
        var makeMerchantUid = hours +  minutes + seconds + milliseconds;
        
        var title = document.getElementById('order_product_title').value;
        
        function requestPay() {
        	            
            IMP.request_pay({
                pg : 'kcp',
                pay_method : 'card',
                merchant_uid: "IMP"+makeMerchantUid, 
                name : title,
                //amount : parseInt(${totalprice}),
                amount : 100,
                buyer_email : '${em.user_email}',
                buyer_name : '${em.user_name}',
                buyer_tel : '${em.user_phone}',
                buyer_addr : '서울특별시 강남구 삼성동',
                buyer_postcode : '123-456',
                m_redirect_url: ""
            }, function (rsp) { // callback
                if (rsp.success) {
                    console.log(rsp);
                    console.log("결제 성공");
                    document.getElementById('frm').submit();
                } else {
                    console.log(rsp);
                    console.log("결제 실패");
                    alert("실패");
                }
            });
        }
    </script>
</body>
</html>
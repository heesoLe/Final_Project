<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%> <%-- JSTL 태그립 추가 --%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.8.2/css/all.min.css"> <%-- CDN 절대링크 --%>

<title>HealhtJAva 찜 목록</title>

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
	/******************/
	p {
		margin: 0.75rem 0 0;
	}
	
	input, button {
		border: 0 none;
		outline: 0 none;
	}
	
	.summary-checkout button {
		background-color: #666;
		color: #fff;
	}
	
	.summary-checkout button:hover, .summary-checkout button:focus {
		background-color: #555;
	}
	
	.product-image img, .basket-labels, .basket-product {
		width: 100%;
	}
	
	input, .summary-checkout button, .basket, .basket-module, .basket-labels,
		.item, .price, .quantity, .subtotal, .basket-product, .product-image,
		.product-details {
		float: left;
	}
	
	.hide {
		display: none;
	}
	
	main {
		clear: both;
		font-size: 0.75rem;
		margin: 0 auto;
		overflow: hidden;
		padding: 1rem 0;
		width: 960px;
	}
	
	.basket, .aside_right {
		padding: 0 1rem;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		box-sizing: border-box;
	}
	
	.basket {
		width: 100%;
		padding-bottom: 20px;
		height: 900px;
	}
	
	.basket-module {
		color: #111;
	}
	
	label {
		display: block;
		margin-bottom: 0.3125rem;
	}
	
	.promo-code-field {
		border: 1px solid #ccc;
		padding: 0.5rem;
		text-transform: uppercase;
		transition: all 0.2s linear;
		width: 48%;
		-webkit-box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
		-moz-box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
		-o-box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
		box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
	}
	
	.promo-code-field:hover, .promo-code-field:focus {
		border: 1px solid #999;
	}
	
	.promo-code-cta {
		border-radius: 4px;
		font-size: 0.625rem;
		margin-left: 0.625rem;
		padding: 0.6875rem 1.25rem 0.625rem;
	}
	
	.basket-labels {
		border-top: 1px solid #ccc;
		border-bottom: 1px solid #ccc;
		margin-top: 1.625rem;
	}
	
	.basket-labels ul {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	
	.basket-labels li {
		color: #111;
		display: inline-block;
		padding: 0.625rem 0;
	}
	
	.basket-labels li.price:before, .basket-labels li.subtotal:before {
		content: '';
	}
	
	.item {
		width: 75%;
	}
	
	.price, .quantity, .subtotal {
		width: 15%;
	}
	
	.subtotal {
		text-align: right;
	}
	
	.btnAdd {
		margin-left: 50px;
		font-size: 22px;
	}
	
	/* 삭제 버튼 */
	.removeCart {
		bottom: 1.125rem;
		float: right;
		position: absolute;
		right: 0;
		text-align: right;
		width: 10%;
		height: 30%;
		margin-right: 8px;
		background-color: white;
		border-radius: 5px;
		border: 1px solid black;
		font-size: 22px;
		text-align: center;
	}
	
	.removeCart:hover {
		cursor: pointer;
	}
	/* 삭제 글자 */
	.removeText {
		font-size: 15px;
		position: relative;
		top: -5%;
	}
	
	/* 담기 버튼 */
	.addCart {
		bottom: 1.125rem;
		float: right;
		position: absolute;
		right: 11%;
		text-align: right;
		width: 10%;
		height: 30%;
		margin-right: 8px;
		background-color: white;
		border-radius: 5px;
		border: 1px solid rgb(217, 217, 217);
		font-size: 22px;
		text-align: center;
	}
	
	.addCart:hover {
		cursor: pointer;
	}
	
	.addText {
		font-size: 15px;
		position: relative;
		top: -10%;
	}
	/* 담기 이미지 위치 */
	#shopping_cartImg {
		width: 25px;
		height: 25px;
		margin: 8px 10px 10px 15px;
	}
	
	/* 삭제 이미지 위치 */
	#shopping_deleteImg {
		width: 25px;
		height: 25px;
		margin: 8px 10px 10px 15px;
	}
	
	.remove button {
		background-color: transparent;
		float: none;
		text-decoration: none;
		text-transform: uppercase;
	}
	
	.item-heading {
		padding-left: 4.375rem;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		box-sizing: border-box;
		text-align: left;
		width: 25px;
	}
	
	.item-heading2 {
		position: relative;
		left: -44.5%;
	}
	
	.basket-product {
		border-bottom: 1px solid #ccc;
		padding: 1rem 0;
		position: relative;
	}
	
	.product-image {
		width: 90px;
	}
	
	.product-frame {
		border: 1px solid #aaa;
	}
	
	.product-details {
		padding: 0 1.5rem;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		box-sizing: border-box;
		width: 75%;
		padding-left: 5px;
		text-align: left;
		margin: 5px 0px 0px 8px;
	}
	
	.quantity-field {
		background-color: #ccc;
		border: 1px solid #aaa;
		border-radius: 4px;
		font-size: 0.625rem;
		padding: 2px;
		width: 3.75rem;
		margin-left: 30px;
	}
	
	.aside_right {
		float: right;
		position: relative;
		width: 30%;
	}
	
	.summary {
		background-color: #eee;
		border: 1px solid #aaa;
		padding: 1rem;
		position: fixed;
		width: 250px;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		box-sizing: border-box;
		margin-top: 25px;
	}
	
	.summary-total-items {
		color: #666;
		font-size: 0.875rem;
		text-align: center;
	}
	
	.summary-subtotal, .summary-total {
		border-top: 1px solid #ccc;
		border-bottom: 1px solid #ccc;
		clear: both;
		margin: 1rem 0;
		overflow: hidden;
		padding: 0.5rem 0;
	}
	
	.subtotal-title, .subtotal-value, .total-title, .total-value,
		.promo-title, .promo-value {
		color: #111;
		float: left;
		width: 50%;
	}
	
	.summary-promo {
		-webkit-transition: all .3s ease;
		-moz-transition: all .3s ease;
		-o-transition: all .3s ease;
		transition: all .3s ease;
	}
	
	.promo-title {
		float: left;
		width: 70%;
	}
	
	.promo-value {
		color: #8B0000;
		float: left;
		text-align: right;
		width: 30%;
	}
	
	.summary-delivery {
		padding-bottom: 3rem;
	}
	
	.subtotal-value, .total-value {
		text-align: right;
	}
	
	.total-title {
		font-weight: bold;
		text-transform: uppercase;
	}
	
	.summary-checkout {
		display: block;
	}
	
	.checkout-cta {
		display: block;
		float: none;
		font-size: 0.75rem;
		text-align: center;
		text-transform: uppercase;
		padding: 0.625rem 0;
		width: 100%;
	}
	
	.summary-delivery-selection {
		background-color: #ccc;
		border: 1px solid #aaa;
		border-radius: 4px;
		display: block;
		font-size: 0.625rem;
		height: 34px;
		width: 100%;
	}
	
	.total-title {
		text-align: left;
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
	
	#subspan {
		color: #808080;
	}
	
	.memBasicInfo1 {
		height: 120px;
		width: 120px;
		padding: 20px;
		float: left;
		margin-right: 200px;
		margin-top: 0px;
	}
	
	.memBasicInfo2 {
		height: 80px;
		width: 130px;
		position: relative;
		top: -40%;
		left: 50%;
	}
	
	.innerWrap {
		width: 300px;
		height: 220px;
		padding: 20px;
		float: left;
		margin-left: 60px;
		overflow: hidden;
	}
	
	#mypageTitle {
		font-size: 28px;
		font-weight: 700;
	}
	
	.mypageTitlebox {
		float: left;
		margin: 20px 0px 0px 5px;
	}
	
	#user_id {
		font-size: 20px;
		font-weight: 700;
	}
	/* 찜 목록 */
	.wishBox {
		margin-left: 0;
		width: 1200px;
		position: relative;
		left: 40%;
		top: 4%;
		transform: translateX(-50%);
		overflow: hidden;
		border-bottom: 2px solid rgb(217, 217, 217);
	}
	/* 찜한 상품 */
	#listTitle {
		font-size: 1.8em;
		font-weight: bold;
		margin-left: 15px;
	}
	
	.listTitleBox {
		width: 100%;
		height: 60px;
		border-bottom: 2px solid rgb(217, 217, 217);
		text-align: left;
	}
	/* 체크박스 */
	/*input 은 숨겨주기*/
	input#chk_all {
		display: none;
	}
	/*input 바로 다음의 label*/
	input#chk_all+label {
		cursor: pointer;
	}
	
	/*input 바로 다음의 label:before 에 체크하기 전 CSS 설정*/
	input#chk_all+label:before {
		content: "";
		display: inline-block;
		width: 18px;
		height: 18px;
		line-height: 18px;
		border: 1px solid #cbcbcb;
		vertical-align: middle; /*체크 전과 체크 후 높이 차이 때문에 설정*/
	}
	
	/*checked된 input 바로 다음의 label:before 에 체크 후 CSS 설정*/
	input#chk_all:checked+label:before {
		content: "\f00c"; /*폰트어썸 유니코드*/
		font-family: "Font Awesome 5 free"; /*폰트어썸 아이콘 사용*/
		font-weight: 900; /*폰트어썸 설정*/
		color: #AC76B0;
		background-color: white;
		border-color: #000;
		font-size: 13px;
		text-align: center;
	}
	
	input#chk_select {
		display: none;
	}
	/*input 바로 다음의 label*/
	input#chk_select+label {
		cursor: pointer;
	}
	
	/*input 바로 다음의 label:before 에 체크하기 전 CSS 설정*/
	input#chk_select+label:before {
		content: "";
		display: inline-block;
		width: 18px;
		height: 18px;
		line-height: 18px;
		border: 1px solid #cbcbcb;
		vertical-align: middle; /*체크 전과 체크 후 높이 차이 때문에 설정*/
	}
	
	/*checked된 input 바로 다음의 label:before 에 체크 후 CSS 설정*/
	input#chk_select:checked+label:before {
		content: "\f00c"; /*폰트어썸 유니코드*/
		font-family: "Font Awesome 5 free"; /*폰트어썸 아이콘 사용*/
		font-weight: 900; /*폰트어썸 설정*/
		color: #AC76B0;
		background-color: white;
		border-color: #000;
		font-size: 13px;
		text-align: center;
	}
	/*checked된 input 바로 다음의 label:before 에 체크 후 CSS 설정*/
	input#chk_all:checked+label:before {
		content: "\f00c"; /*폰트어썸 유니코드*/
		font-family: "Font Awesome 5 free"; /*폰트어썸 아이콘 사용*/
		font-weight: 900; /*폰트어썸 설정*/
		color: #AC76B0;
		background-color: white;
		border-color: #000;
		font-size: 13px;
		text-align: center;
	}
	
	#chk_selectLabel {
		float: left;
		margin-right: 10px;
	}
	
	.product-details a {
		text-decoration: none;
		color: black;
	}
	
	.product-details a:hover {
		text-decoration: underline;
		color: black;
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
	
	#allDelete {
		background-color: white;
		font-size: 15px;
		font-weight: 600;
	}
	
	#allDelete:hover {
		cursor: pointer;
	}/* 'PREV' 전체 틀 */
	#pagination a {
		position: relative;
		display: inline-block;
		color: #B21948; /* 글자색상 */
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
		background-color: #B21948;
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
	}
	
	#pagination #pagination-active {
		color: #fff;
	}
	
	#pagination #pagination-active:before {
		-webkit-transform: scale(1);
		transform: scale(1);
	}
	/*'NEXT' 전체 틀 */
	#pagination-newer {
		margin-right: 50px;
	}
	
	#pagination-older {
		margin-left: 50px;
	}
	.productList tr{
		border-bottom: 1px solid #B21948;
	}
	.meau {
		padding-top: 30px;
		padding-left: 800px;
		font-family: 'KIMM_Bold';
	}
	
	.meau a {
		color: white;
		text-decoration: none;
	}
	select {
		padding : 5px 5px;
	}
	
	.nonList {
		font-size: 15px;
		border-top: 1px solid #e7e7e7;
		text-align: center;
	    padding: 140px 0 36px;
	    background: url(../images/bg_no_list.png) no-repeat 50% 40px;
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
							<li><a href="myPage_like" class="liList" style="color: #B21948;">찜 목록</a></li>
							<li><a href="myPage_cart" class="liList" >장바구니</a></li>
							<li><a href="myPage_review" class="liList">나의 상품후기</a></li>
	
							<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 회원 정보</li>
							<li><a href="myPage_updateInfo" class="liList">회원정보 변경</a></li>
							<li><a href="myPage_changePwd" class="liList">비밀번호 변경</a></li>
							<li><a href="myPage_user_Withdrawal" class="liList">회원탈퇴</a></li>
							<li style="margin-bottom: 30px;"><a href="myPage_updateAddress" class="liList">배송지 관리</a></li>
							
							<!-- <li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 나의 상품후기</li> -->
						</ul>
					</nav>
				</aside>
				<%-- 본문 영역 --%>
				<div class="wishBox">
					<div class="listTitleBox">
						<span id="listTitle">찜 목록</span>
					</div>

					<div class="basketcontentBox">
						<div class="basket">
							<div class="basket-labels">
								<ul>
									<li class="item item-heading">
										<%-- 체크 박스 --%>
										<input type="checkbox" name="chk_all" id="chk_all" /><label for="chk_all" style="width: 20px;"></label>
										<script>
											$("#chk_all").click(function(){
											 var chk = $("#chk_all").prop("checked");
											 if(chk) {
											  $(".chBox").prop("checked", true);
											 } else {
											  $(".chBox").prop("checked", false);
											 }
											});
										</script>
									</li>
									<li class="item-heading2">
										<button id="allDelete">선택 항목 삭제</button>
										<script>
											$("#allDelete").click(function(){
												var confirm_val = confirm("정말 삭제하시겠습니까?");
											 
												if(confirm_val) {
													var checkArr = new Array();
											  
													$("input[class='chBox']:checked").each(function(){
														checkArr.push($(this).attr("data-cartNum"));
													});
											   
													$.ajax({
														url : "deleteOK.shop", // deleteOK?
														type : "post",
														data : { chbox : checkArr },
														success : function(){
															location.href = "like"; // 현재 페이지로 새로고침
														}
													});
												} 
											});
										</script>
									</li>
								</ul>
							</div>
							<div class="basket-product"> <%-- 체크 박스 --%>
								<input type="checkbox" id="chk_select" name="chBox" class="chBox" data-cartNum="${cartList.cartNum}"/><label for="chk_select" id="chk_selectLabel"></label> <%-- 체크 박스 끝 --%>
								
								<%-- 찜목록 출력 --%>
								<table>
										<tr height="40px;" style="border-bottom: 2px solid #e7e7e7;">
											<th width="85px;">No</th>
											<th width="100px;"></th>
											<th width="500px;">제품명</th>
											<th width="200px;">금액</th>
											<th width="300px;">비고</th>
										</tr>
									<c:if test="${!empty Llist}">
									<c:forEach var="l" items="${Llist}">
										<tr height="40px;" >
											<td>${l.like_no}</td>
											<td class="product-image">
												<img src="/upload${l.product_cont1 }" alt="상품 이미지" class="product_frame"> 
												
											</td>
											<td>
											<a href="product/detail/${l.product_no }">${l.product_title}</a>
											</td>
											<td class="product_details"><span id="productTitle"><strong style="font-size: 20px;">${l.product_price} 원</strong></span></td>

											<td>
												<%-- <button class="addCart" onclick="addOk()">
													<img id="shopping_cartImg" src="<%=request.getContextPath()%>/images/shopping_cart.png" alt="쇼핑 카트"> 
													<span class="addText">담기</span>
												</button> --%>
												
												<button onclick="location='likeDel?like_no=${l.like_no}';">
													<img id="shopping_deleteImg" src="<%=request.getContextPath()%>/images/recycle_bin.png" alt="휴지통"> 
													<span class="removeText" >삭제</span>
												</button>
											</td>
											<td>
												
											</td>
										</tr>
									</c:forEach>
									</c:if>
									
									<c:if test="${empty Llist}">
									<tr height="40px;" >
										<th colspan="5" class="nonList">현재 주문한 제품이 없습니다.</th>
									</tr>
								</c:if>
								</table>

							</div>
						
				<%-- 페이징 처리 --%>
				<div id="pagination">
				    <c:if test="${page <= 1}">
				        PREV&nbsp;
				    </c:if>
				    <c:if test="${page > 1}">
				        <a href="myPage_like?page=${page-1}">PREV</a>&nbsp;
				    </c:if>
				    
				    <!-- 현재 쪽번호 출력 -->
				    <c:forEach var="a" begin="${startpage}" end="${endpage}" step="1">
				        <c:if test="${a == page}"> <%-- 현재 페이지가 선택된 경우 --%>
				            [&nbsp;${a}&nbsp;]
				        </c:if>
				        <c:if test="${a != page}"> <%-- 현재 쪽번호가 선택 안 된 경우 --%>
				            <a href="myPage_like?page=${a}">[&nbsp;${a}&nbsp;]</a>&nbsp;
				        </c:if>
				    </c:forEach>	                   
				    
				    <c:if test="${page >= maxpage}">
				        &nbsp;NEXT
				    </c:if>
				    <c:if test="${page < maxpage}">
				        <a href="myPage_like?page=${page+1}">NEXT</a>
				    </c:if>
				</div> <%-- end 페이징처리 --%>
				
				 </div>
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
			
		<%-- 삭제 버튼 클릭 시 confirm창 띄우기 --%>
		function deleteOk() {
			var result = confirm('찜 목록에서 삭제하시겠습니까?');
			
			if(result == true) {
				alert("찜 목록에서 삭제되었습니다.");
			} else {
				alert("삭제가 취소되었습니다.");
			}
		}
		
		<%-- 담기 버튼 클릭 시 confirm창 띄우기 --%>
		function addOk() {
			var result = confirm('장바구니에 추가하시겠습니까?');
			
			if(result == true) {
				alert("추가가 되었습니다.");
			} else {
				alert("추가가 취소되었습니다.");
			}
		}
		
	</script>
</body>
</html>
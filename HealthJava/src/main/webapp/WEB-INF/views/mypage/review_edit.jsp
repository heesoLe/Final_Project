<%@ page contentType="text/html; charset=UTF-8" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.8.2/css/all.min.css"> <%-- CDN 절대링크 --%>

<title>PuppyHome 리뷰 작성</title>

<link rel="stylesheet" type="text/css" href=""> <%-- certificate.css --%>
<style type="text/css">
	/* 폰트 CSS */
	@font-face {
		font-family: 'KIMM_Bold';
		src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2') format('woff2'); /* CDN 절대링크  */
		font-weight: 700;
		font-style: normal;
	}
	* {
		font-family: 'KIMM_Bold', sans-serif;
	}
	.wrap {
		width: 490px;
		height: 880px;
	}
	.headerBox {
		width: 100%;
		height: 50px;
		text-align: center;
		border-bottom: 0.5px solid rgb(215, 215, 215);
	}
	.titleBox {
		margin-top: 8.5px;
	}
	#titleText {
		font-size: 20px;
		font-weight: 700;
	}
	.productBox {
		height: 110px;
	}
	.vacuumBox {
		height: 10px;
		background: rgb(244, 244, 244);
	}
	.questionBox {
		height: 52px;
		text-align: center;
	}
	.questionBox2 {
		margin-top: 20px;
	}
	#questionText {
		font-size: 20px;
		font-weight: 700;
	}
	.starBox {
		height: 100px;
	}
	.starInputBox {
		height: 68px;
	}
	.starInputBox2 {
		width: 280px;
		height: 67.5px;
		margin: auto;
		text-align: center;
	}
	.starTextBox {
		width: 80px;
		margin: auto;
	}
	#starText {
		font-size: 14px;
		color: rgb(215, 215, 215);
	}
	label {
		height: 50px;
	}
	.question-reviewBox {
		height: 75px;
	}
	.question-reviewBox2 {
		height: 46px;
		text-align: center;
	}
	.question-reviewBox3 {
		text-align: center;
	}
	#question-reviewText {
		font-size: 20px;
		font-weight: 700;
	}
	.writeReviewBox {
		height: 190px;
	}
	.writeReviewBox2 {
		width: 440px;
		height: 180px;
		margin: 10px 0px 0px 28px;
		background: rgb(244, 244, 244);
		border: 0.5px solid rgb(203, 203, 203);
	}
	#reviewContent {
		width: 400px;
		height: 120px;
		background: rgb(244, 244, 244);
		margin: 15px 16px 0px 16px;
		border: 0;
		resize: none;
	}
	.attachBox {
		height: 170px;
	}
	.attachBox2 {
		width: 440px;
		height: 114px;
		margin: 30px 0px 0px 28px;
	}
	#uploadInput {
		position: relative;
		top: 30%;
		visibility: hidden;
	}
	#uploadBtn {
		width: 100%;
		height: 48%;
		font-size: 20px;
		font-weight: 700;
		border: 1px dashed;
	}
	.attachTextBox {
		margin-top: 10px;
	}
	#attachText {
		font-size: 14px;
		color: red;
	}
	.buttonBox {
		height: 60px;
	}
	.buttonBox2 {
		width: 437px;
		height: 80px;
		margin-left: 30px;
	}
	#cancelBtn {
		width: 215px;
		height: 50px;
		background: white;
		border: 1px solid rgb(203, 203, 203);
	}
	#okBtn {
		width: 215px;
		height: 50px;
		color: white;
		background: rgb(215, 215, 215);
		border: 1px solid rgb(203, 203, 203);
	}
	#myform fieldset{
	    display: inline-block;
	    direction: rtl;
	    border:0;
	}
	#myform fieldset legend{
	    text-align: right;
	}
	#myform input[type=radio]{
	    display: none;
	}
	#myform label{
	    font-size: 3em;
	    color: transparent;
	    text-shadow: 0 0 0 rgb(215, 215, 215);
	    height: 50px;
		margin-top: -30px;
	}
	#myform label:hover{
	    text-shadow: 0 0 0 rgba(250, 208, 0, 0.99);
	}
	#myform label:hover ~ label{
	    text-shadow: 0 0 0 rgba(250, 208, 0, 0.99);
	}
	#myform input[type=radio]:checked ~ label{
	    text-shadow: 0 0 0 rgba(250, 208, 0, 0.99);
	}
	.productBox {
		width: 100%;
	}
	.item {
  		width: 100%;
  		float: left;
	}
	.basket-product {
		width: 100%;
	 	float: left;
	}
	.product-image img {
  		width: 100%;
	}
	.product-image {
	 	width: 70px;
	 	margin: 14px 0px 0px 10px;
	}
	#product-frame {
		width: 65px;
	}
	.product-details {
	 	padding: 0 1.5rem;
	 	width: 400px;
	 	height: 30px;
	 	padding-left: 5px;
	 	text-align: left;
	 	margin: 5px 0px 0px 0px;
	}
	.detailsBox1 {
		width: 80px;
		float: left;
	}
	.detailsBox2 {
		width: 390px;
		float: left;
		margin-top: 10px;
	}
	#productTitle {
		float: left;
	}
</style>
</head>
<body style="overflow-x:hidden; overflow-y:hidden;">
	<div class="wrap">
		<div class="headerBox">
				<span id="titleText">리뷰쓰기</span>
			</div>
		</div>
		<div class="productBox">
			<div class="basket-product">
				<div class="item">
					<div class="detailsBox1">
						<div class="product-image">
							<img src="https://img-cf.kurly.com/cdn-cgi/image/width=676,format=auto/shop/data/goods/1637924624422l0.jpeg" alt="상품 이미지" id="product-frame" class="product-frame">
						</div>
					</div>
					<div class="detailsBox2">
						<div class="product-details">
							<span id="productTitle">2023.03.29</span>
						</div>
						<div class="product-details">
							<span id="productTitle"><strong>청송 사과 1.5kg(5~7입)</strong></span>
						</div>
					</div>
				</div>
			</div>
		</div>
		<div class="vacuumBox">
		
		</div>
		<div class="questionBox">
			<div class="questionBox2">
				<span id="questionText">상품은 만족하셨나요?</span>
			</div>
		</div>
		<form class="mb-3" name="myform" id="myform" method="post">
		<div class="starBox">
			<div class="starInputBox">
				<div class="starInputBox2">
					<fieldset>
						<input type="radio" name="reviewStar" value="5" id="rate1"><label for="rate1">★</label>
						<input type="radio" name="reviewStar" value="4" id="rate2"><label for="rate2">★</label>
						<input type="radio" name="reviewStar" value="3" id="rate3"><label for="rate3">★</label>
						<input type="radio" name="reviewStar" value="2" id="rate4"><label for="rate4">★</label>
						<input type="radio" name="reviewStar" value="1" id="rate5"><label for="rate5">★</label>
						<br>
						<div class="starTextBox">
							<span id="starText">.선택하세요</span>
						</div>
					</fieldset>
				</div>
			</div>
		</div>
		<div class="question-reviewBox">
			<div class="question-reviewBox2">
				<span id="question-reviewText">만족도 3점을 주셨네요.</span>
				<div class="question-reviewBox3">
					<span id="question-reviewText">어떤 점이 좋았나요?</span>
				</div>
			</div>
		</div>
		<div class="writeReviewBox">
			<div class="writeReviewBox2">
				<textarea id="reviewContent" placeholder="최소 10자 이상 입력해주세요."></textarea>
			</div>
		</div>
		<div class="attachBox">
			<div class="attachBox2">
				<input id="uploadInput" type="file">
				<button id="uploadBtn" onclick="onClickUpload();">사진/동영상 첨부하기</button>
				<div class="attachTextBox">
					<span id="attachText">상품과 무관한 사진/동영상을 첨부한 리뷰는 통보없이 삭제 및 적립<br>혜택이 회수됩니다.</span>
				</div>
			</div>
		</div>
		</form>
	    <div class="footerBox">
			<div class="buttonBox">
				<div class="buttonBox2">
					<button id="cancelBtn" onclick="closeWindow();">취소</button>
					<button id="okBtn">등록</button>
				</div>
			</div>
	    </div>
	</div>
</body>
<script>
	function onClickUpload() {
	    let uploadInput = document.getElementById("uploadInput");
	    uploadInput.click();
	}
    function closeWindow() {
        window.close();
    }
</script>
</html>
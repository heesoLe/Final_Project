<%@ page contentType="text/html; charset=UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<!-- BootStrap -->
<link
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css"
    rel="stylesheet"
    integrity="sha384-gH2yIJqKdNHPEq0n4Mqa/HGKIhSkIHeL5AyhkYV8i59U5AR6csBvApHHNl/vI1Bx"
    crossorigin="anonymous">
</head>
<body>
    <div
        class="d-flex flex-column min-vh-100 justify-content-center align-items-center">
        <div class="row justify-content-center">
            <form action="${pageContext.request.contextPath}/login" method="post">
                <!-- 아이디 -->
                <input class="form-control my-2" type="text" placeholder="아이디" name="id">
                <!-- 패스워드 -->
                <input class="form-control my-2" type="password" placeholder="패스워드" name="pw">
                <div class="row justify-content-between">
                    <button class="col-4 ms-2 btn btn-sm btn-outline-primary" type="button" id="btn_join">회원가입</button>
                    <button class="col-4 me-2 btn btn-sm btn-outline-primary"  type="submit">로그인</button>
                </div>
            </form>
        </div>
    </div>
</body>
<!-- BootStrap -->
<script
    src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.bundle.min.js"
    integrity="sha384-A3rJD856KowSb7dwlZdYEkO39Gagi7vIsF0jrRAoQmDKKtQBHUuLZ9AsSv4jD4Xa"
    crossorigin="anonymous"></script>
<!-- JQuery -->
<script src="https://code.jquery.com/jquery-3.6.1.js"
    integrity="sha256-3zlB5s2uwoUzrXK3BT7AX3FyvojsraNFxCc2vC/7pNI="
    crossorigin="anonymous"></script>
<script>
    const btnJoin = document.querySelector('#btn_join');
    console.log(btnJoin);

    btnJoin.addEventListener('click', function() {
        location.href = "${pageContext.request.contextPath}/join";
    });
</script>
</html>
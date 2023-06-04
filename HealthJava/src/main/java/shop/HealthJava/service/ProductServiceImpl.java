package shop.HealthJava.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import shop.HealthJava.dao.ProductDAO;
import shop.HealthJava.vo.CartVO;
import shop.HealthJava.vo.LikeVO;
import shop.HealthJava.vo.OrderDetailVO;
import shop.HealthJava.vo.ProductVO;
import shop.HealthJava.vo.ProductQnAVO;

@Service
public class ProductServiceImpl implements ProductService {
	
	@Autowired
	private ProductDAO productDao;

	

	@Override
	public ProductVO getProductContent(int product_no) {
		
		return this.productDao.getProductContent(product_no);
	}

	@Override
	public void insertProduct(ProductVO f) {
		
		this.productDao.insertProduct(f);
		
	}

	@Override
	public void deleteProduct(int product_no) {
		this.productDao.deleteProduct(product_no);
		
	}

	@Override
	public void updateProduct(ProductVO f) {
		this.productDao.updateProduct(f);
		
	}


	@Override
	public List<ProductQnAVO> getReviewList(int product_no) {
		// TODO Auto-generated method stub
		return this.productDao.getReviewList(product_no);
	}

	@Override
	public void insertQna(ProductQnAVO f) {
		// TODO Auto-generated method stub
		this.productDao.insertQna(f);
	}

	@Override
	public void insertLike(LikeVO f) {
		this.productDao.insertLike(f);
		
	}

	@Override
	public void deleteLike(LikeVO f) {
		this.productDao.deldteLike(f);
		
	}

	@Override
	public LikeVO getLikeList(LikeVO f) {
		// TODO Auto-generated method stub
		return this.productDao.getLikeList(f);
	}

	@Override
	public void insertCart(CartVO c ) {
		this.productDao.insertCart(c);
		
	}

	@Override
	public void insertOrderDetail(OrderDetailVO o) {
		this.productDao.insertOrderDetail(o);
		
	}

	@Override
	public List<ProductVO> getListNew(ProductVO f, String kind, String kind2) {
		return this.productDao.getListNew(f,kind,kind2);
		
	}

	@Override
	public int getTotalItems(ProductVO f, String kind, String kind2) {
		// TODO Auto-generated method stub
		return this.productDao.getTotalItems(f, kind, kind2);
	}
	
}

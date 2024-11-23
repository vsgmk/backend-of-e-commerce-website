from django.shortcuts import render
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from rest_framework import generics, status
from rest_framework.response import Response
from django.core.mail import send_mail
import random
from .models import CustomUser, OTP
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

# User Registration View
class UserRegistrationView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()

    def create(self, request, *args, **kwargs):
        # Extract user data from request
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        middle_name = request.data.get('middle_name')
        date_of_birth = request.data.get('date_of_birth')
        gender = request.data.get('gender')
        contact_number = request.data.get('contact_number')
        hobbies = request.data.get('hobbies')
        address = request.data.get('address')
        language = request.data.get('language')

        # Create the user instance
        user = CustomUser(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            date_of_birth=date_of_birth,
            gender=gender,
            contact_number=contact_number,
            hobbies=hobbies,
            address=address,
            language=language,
        )
        user.set_password(password)  # Hash the password
        user.save()  # Save the user instance

        # Generate and send OTP
        otp_code = random.randint(100000, 999999)
        OTP.objects.create(user=user, otp_code=otp_code)
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp_code}',
            'vaibhavsurvase674@gmail.com',  # Replace with your actual email
            [user.email],
            fail_silently=False,
        )

        # Return the user ID and a success message
        return Response({
            'id': user.id,  # User ID
            'message': 'User registered successfully. OTP sent to email.'
        }, status=status.HTTP_201_CREATED)


# OTP Verification View
class VerifyOTPView(APIView):
    def post(self, request, *args, **kwargs):
        otp_code = request.data.get('otp_code')
        user_id = request.data.get('user_id')

        try:
            otp = OTP.objects.get(user_id=user_id, otp_code=otp_code)
            if not otp.is_verified:
                otp.is_verified = True
                otp.save()
                return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "OTP is already verified."}, status=status.HTTP_400_BAD_REQUEST)
        except OTP.DoesNotExist:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)


# User Login View
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        print(f"Attempting to log in with username: {username}")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)

            return Response({
                'message': 'Login successful!',
                'refresh': str(refresh),
                'access': access,
            }, status=status.HTTP_200_OK)
        else:
            print("Authentication failed: Invalid credentials.")
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


# User Logout View
def logout_view(request):
    logout(request)
    return JsonResponse({'message': 'Logout successful'}, status=200)


# Home/Dashboard View
@login_required
def dashboard_view(request):
    return render(request, 'dashboard.html')


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import CustomUser

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    user = request.user
    
    if request.method == 'GET':
        # Return the user's profile data
        user_data = {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'contact_number': user.contact_number,
            'hobbies': user.hobbies,
            'address': user.address,
        }
        return Response(user_data)

    elif request.method == 'PUT':
        # Update user's profile
        data = request.data
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.contact_number = data.get('contact_number', user.contact_number)
        user.hobbies = data.get('hobbies', user.hobbies)
        user.address = data.get('address', user.address)
        user.save()

        return Response({"success": "Profile updated successfully"})



# User Settings View
@login_required
def settings_view(request):
    context = {
        'user': request.user,
    }
    return render(request, 'settings.html', context)


from django.shortcuts import render
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from rest_framework import generics, status
from rest_framework.response import Response
from django.core.mail import send_mail
import random
from .models import CustomUser, OTP
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

# Password Reset Request View
class PasswordResetRequestView(APIView):
    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        
        try:
            user = CustomUser.objects.get(username=username, email=email)
            # Generate and send OTP
            otp_code = random.randint(100000, 999999)
            # Create or update OTP object, resetting is_verified to False
            OTP.objects.update_or_create(user=user, defaults={'otp_code': otp_code, 'is_verified': False})
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp_code}',
                'vaibhavsurvase674@gmail.com',  # Replace with your actual email
                [user.email],
                fail_silently=False,
            )
            return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Password Reset View
class PasswordResetView(APIView):
    def post(self, request):
        username = request.data.get('username')
        otp_code = request.data.get('otp_code')
        new_password = request.data.get('new_password')
        
        try:
            # Fetch the user based on the username
            user = CustomUser.objects.get(username=username)
            # Check for the OTP and make sure it's not verified yet
            otp = OTP.objects.get(user=user, otp_code=otp_code, is_verified=False)

            # Mark OTP as verified
            otp.is_verified = True
            otp.save()

            # Update the user's password
            user.set_password(new_password)  # Hash the new password
            user.save()

            # Optionally delete OTP after it's verified and used
            otp.delete()

            return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
                
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid or unverified OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
from .models import Product

class GetProductView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        product_id = kwargs.get('product_id')

        if product_id:
            try:
                # Fetch the product by ID
                product = Product.objects.get(id=product_id)
                # Build the absolute image URL with the specific condition
                image_url = f'{settings.MEDIA_URL}+{str(product.image)}' if product.image else None
                print(f"Image URL for product {product.id}: {image_url}")  # This will output the image URL in the terminal
                product_data = {
                    'id': product.id,
                    'name': product.name,
                    'description': product.description,
                    'price': product.price,
                    'image': image_url,
                }
                return Response({'product': product_data}, status=200)
            except Product.DoesNotExist:
                return Response({'error': 'Product not found'}, status=404)
        else:
            # Fetch all products if no ID is provided
            products = Product.objects.all()
            products_data = [
                {
                    'id': product.id,
                    'name': product.name,
                    'description': product.description,
                    'price': product.price,
                    'image': f'{settings.MEDIA_URL}{str(product.image)}' if product.image else None,
                }
                for product in products
            ]
            return Response({'products': products_data}, status=200)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Cart, CartItem, Product
from rest_framework import status
import json

class AddToCartView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            data = request.data
            product_id = data.get('product_id')
            quantity = data.get('quantity', 1)

            if not product_id:
                return Response({"error": "Product ID is required"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                product = Product.objects.get(id=product_id)
            except Product.DoesNotExist:
                return Response({"error": "Product not found."}, status=status.HTTP_404_NOT_FOUND)

            cart, created = Cart.objects.get_or_create(user=request.user)

            cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)
            if not created:
                cart_item.quantity += quantity
                cart_item.save()

            return Response({"message": "Product added to cart.", "cart_items_count": cart.items.count()})

        except json.JSONDecodeError:
            return Response({"error": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)


from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

@api_view(['GET'])
def check_token(request):
    # This will only be accessible if the token is valid
    return Response({'message': 'Token is valid'})

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from .models import Cart, Product
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from .models import CartItem  # Adjust based on your model

@csrf_protect
def remove_from_cart(request):
    if request.method == 'DELETE':
        product_id = request.GET.get('product_id')
        if product_id:
            try:
                cart_item = CartItem.objects.get(product_id=product_id)
                cart_item.delete()
                return JsonResponse({'status': 'success'}, status=200)
            except CartItem.DoesNotExist:
                return JsonResponse({'error': 'Product not found'}, status=404)
        return JsonResponse({'error': 'Product ID not provided'}, status=400)
    return JsonResponse({'error': 'Invalid method'}, status=405)

# Optional: Clear all items in the cart (if needed)
@require_http_methods(["DELETE"])
@login_required
def clear_cart(request):
    try:
        cart = Cart.objects.filter(user=request.user).first()
        if not cart:
            return JsonResponse({'error': 'Cart not found for the user.'}, status=404)
        
        # Remove all products from the cart
        cart.products.clear()

        # Optionally, delete the cart if it's empty
        if cart.products.count() == 0:
            cart.delete()
        
        return JsonResponse({'message': 'Cart cleared successfully.'})
    
    except Exception as e:
        return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=500)
    
class CartListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        print(f"Authenticated user: {request.user}")
        user = request.user
        if not user.is_authenticated:
            return Response({"error": "Unauthorized"}, status=401)
        
        cart_items = CartItem.objects.filter(cart__user=user)
        cart_list = []
        for item in cart_items:
            cart_list.append({
                'id': item.id,
                'product_id': item.product.id,
                'product_name': item.product.name,
                'price': str(item.product.price),
                'quantity': item.quantity
            })
        return Response(cart_list)

# views.py
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_superuser_status(request):
    is_superuser = request.user.is_superuser
    return Response({'is_superuser': is_superuser})


# views.py
from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from .models import Product

class AddProductView(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can add a product

    def post(self, request, *args, **kwargs):
        # Ensure the user is a superuser (admin)
        if not request.user.is_superuser:
            return JsonResponse({'error': 'You do not have permission to add a product.'}, status=403)

        # Extract product data from the request
        product_name = request.data.get('name')
        description = request.data.get('description')
        price = request.data.get('price')
        image = request.data.get('image')  # Assuming the image comes as base64 or file field

        # Validate the input data
        if not product_name or not price or not description:
            return JsonResponse({'error': 'Missing required fields.'}, status=400)

        try:
            price = float(price)
        except ValueError:
            return JsonResponse({'error': 'Invalid price format.'}, status=400)

        # Create the product
        product = Product.objects.create(
            name=product_name,
            description=description,
            price=price,
            image=image
        )

        # Return success response with product data
        return JsonResponse({
            'message': 'Product added successfully!',
            'product': {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'image': product.image.url if product.image else None
            }
        }, status=201)


# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Product

class GetProductcartView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access product info

    def get(self, request, *args, **kwargs):
        # Fetch product ID from URL
        product_id = kwargs.get('product_id')
        
        try:
            product = Product.objects.get(id=product_id)  # Get the product by ID
        except Product.DoesNotExist:
            return Response({'error': 'Product not found'}, status=404)
        
        # Serialize product data manually (if you're not using serializers)
        product_data = {
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'image': product.image.url if product.image else None,
        }

        return Response({'product': product_data})

from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from .models import Product

class ProductUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def put(self, request, product_id):
        """
        Handle product update by passing product id in the URL.
        """
        product = get_object_or_404(Product, id=product_id)
        
        # Validate and get product data from request
        name = request.data.get('name', None)
        description = request.data.get('description', None)
        price = request.data.get('price', None)
        
        if not name or not description or not price:
            return Response({'error': 'Name, description, and price are required.'}, status=400)
        
        # Update product details
        product.name = name
        product.description = description
        product.price = price
        
        # Check if an image was uploaded and update it
        if 'image' in request.FILES:
            product.image = request.FILES['image']
        
        product.save()

        return Response({
            'message': 'Product updated successfully.',
            'product': {
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'image': product.image.url if product.image else None
            }
        })


from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Product

class ProductDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, product_id):
        """
        Handle product deletion by passing product id in the URL.
        """
        # Fetch the product by product_id passed in the URL
        product = get_object_or_404(Product, id=product_id)
        product.delete()
        
        return Response({
            'message': 'Product deleted successfully.'
        }, status=status.HTTP_204_NO_CONTENT)



from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.core.files.storage import default_storage
from django.conf import settings
from .models import Product
from django.core.exceptions import ValidationError

class AddProductView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Extract product data
        product_name = request.data.get('name')
        description = request.data.get('description')
        price = request.data.get('price')
        image = request.FILES.get('image')

        # Validate input
        if not product_name or not price or not description:
            return JsonResponse({'error': 'Missing required fields.'}, status=400)

        # Validate price
        try:
            price = float(price)
            if price <= 0:
                return JsonResponse({'error': 'Price must be a positive number.'}, status=400)
        except ValueError:
            return JsonResponse({'error': 'Invalid price format.'}, status=400)

        # Handle the image file
        image_path = None
        if image:
            try:
                image_path = f"products/{image.name}"
                default_storage.save(image_path, image)
            except Exception as e:
                return JsonResponse({'error': f'Error saving image: {str(e)}'}, status=500)

        # Create the product
        try:
            product = Product.objects.create(
                name=product_name,
                description=description,
                price=price,
                image=image_path
            )
        except ValidationError as e:
            return JsonResponse({'error': f'Error creating product: {str(e)}'}, status=400)

        # Return response
        image_url = request.build_absolute_uri(f'{settings.MEDIA_URL}{product.image}') if product.image else None

        return JsonResponse({
            'message': 'Product added successfully!',
            'product': {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'image': image_url
            }
        }, status=201)







# views.py

from django.http import JsonResponse
from .models import Product

def product_list(request):
    # Fetch all products from the database
    products = Product.objects.all()
    
    # Prepare a list to store product data
    product_data = []

    # Loop through the products and prepare a list of dictionaries
    for product in products:
        product_data.append({
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': str(product.price),  # Converting price to string for JSON compatibility
            'image_url': product.image.url if product.image else None,
        })
    
    # Return the product data as JSON
    return JsonResponse({'products': product_data})

from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import HttpResponse
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
from .models import CartItem, PurchaseHistory
from django.shortcuts import get_object_or_404

class PurchaseView(APIView):
    def post(self, request):
        user = request.user

        # Fetch cart items for the authenticated user
        cart_items = CartItem.objects.filter(cart__user=user)  # Assuming CartItem has a ForeignKey to Cart

        # Calculate total price
        total_price = sum(item.product.price * item.quantity for item in cart_items)

        # Save purchase history for each cart item
        for item in cart_items:
            PurchaseHistory.objects.create(user=user, product=item.product, quantity=item.quantity)

        # Clear the user's cart after the purchase
        cart_items.delete()

        # Generate receipt image
        img = Image.new('RGB', (800, 600), color=(255, 255, 255))  # Create a blank white image
        d = ImageDraw.Draw(img)

        # Load a font (fallback to default if not found)
        try:
            font = ImageFont.truetype("arial.ttf", 20)
        except IOError:
            font = ImageFont.load_default()

        # Add receipt header
        d.text((10, 10), "Purchase Receipt", fill=(0, 0, 0), font=font)
        y_offset = 50
        for item in cart_items:
            product_info = f"{item.product.name} - Quantity: {item.quantity} - Price: ₹{item.product.price}"
            d.text((10, y_offset), product_info, fill=(0, 0, 0), font=font)
            y_offset += 30

        # Add the total price at the bottom
        d.text((10, y_offset + 20), f"Total Price: ₹{total_price}", fill=(0, 0, 0), font=font)

        # Convert the image to bytes and return it as a response
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr.seek(0)

        response = HttpResponse(img_byte_arr, content_type='image/png')
        response['Content-Disposition'] = 'attachment; filename="receipt.png"'
        return response


from rest_framework.views import APIView
from django.http import JsonResponse
from .models import PurchaseHistory

class PurchaseHistoryView(APIView):
    def get(self, request):
        user = request.user
        purchases = PurchaseHistory.objects.filter(user=user)

        history_list = []
        for purchase in purchases:
            history_list.append({
                'id': purchase.id,
                'product': {
                    'id': purchase.product.id,
                    'name': purchase.product.name,
                    'price': purchase.product.price
                },
                'quantity': purchase.quantity,
                'purchase_date': purchase.purchase_date.strftime('%Y-%m-%d %H:%M:%S')
            })
        return JsonResponse(history_list, safe=False)


from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Product
from rest_framework.permissions import IsAuthenticated

class ProductListView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request):
        products = Product.objects.all()
        product_data = [
            {
                'id': product.id,
                'name': product.name,
                'price': product.price,
                'description': product.description,
            }
            for product in products
        ]
        return Response(product_data)
    
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Cart, Product

@api_view(['GET'])
@permission_classes([IsAuthenticated])  # Ensures the user is authenticated
def get_cart_data(request):
    try:
        # Fetch the cart items for the authenticated user
        cart_items = Cart.objects.filter(user=request.user)  # Assuming 'Cart' model has 'user' field

        # Prepare the response data
        items_data = []
        total_price = 0

        # Loop through each cart item and fetch its details
        for item in cart_items:
            product = item.product  # Assuming Cart model has a foreign key to Product model
            total_price += item.quantity * product.price  # Calculate total price for each item
            items_data.append({
                'product_id': product.id,
                'product_name': product.name,
                'quantity': item.quantity,
                'price': product.price,
                'total_item_price': item.quantity * product.price,
            })

        # Format the total price to two decimal places
        total_price = round(total_price, 2)

        # Return the cart data
        cart_data = {
            'items': items_data,
            'total': total_price,
        }

        return Response(cart_data)
    
    except Cart.DoesNotExist:
        # In case the user has no cart data
        return Response({"message": "No cart items found."}, status=404)
    except Exception as e:
        # Handle unexpected errors
        return Response({"error": str(e)}, status=500)

from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import Product

# Assuming the Product model has fields: product_id, name, and price
@api_view(['GET'])
def get_product_prices(request):
    product_ids = request.query_params.getlist('product_ids')  # List of product IDs
    products = Product.objects.filter(id__in=product_ids)
    
    product_prices = []
    for product in products:
        product_prices.append({
            'product_id': product.id,
            'name': product.name,
            'price': product.price,
        })
    
    return Response({'product_prices': product_prices})



from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_authentication(request):
    return Response({'authenticated': True, 'user': str(request.user)})



from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)

@csrf_exempt  # Exempt this view from CSRF protection
def process_payment(request):
    try:
        logger.info("Payment request received")

        payment_details = request.data.get('paymentDetails')
        products = request.data.get('products')
        total_price = request.data.get('totalPrice')

        logger.info(f"Payment details: {payment_details}")
        logger.info(f"Products: {products}")
        logger.info(f"Total price: {total_price}")

        if not payment_details or not products or not total_price:
            logger.warning("Missing required payment information")
            return Response({"error": "Missing required payment information"}, status=status.HTTP_400_BAD_REQUEST)

        logger.info("Payment processed successfully")
        return Response({"message": "Payment successful"}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error processing payment: {str(e)}", exc_info=True)
        return Response({"error": "Internal Server Error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Product

@api_view(['GET'])
def get_delivery_info(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
        # Assuming you have a model or a way to calculate delivery info
        delivery_info = {
            'productName': product.name,
            'estimatedDelivery': '5-7 business days',  # Adjust based on your logic
        }
        return Response(delivery_info)
    except Product.DoesNotExist:
        return Response({'error': 'Product not found.'}, status=status.HTTP_404_NOT_FOUND)

from django.http import Http404
from django.shortcuts import render,get_object_or_404
from rest_framework import generics,status
from rest_framework.response import Response
from . import serializers
from .models import Note
# add authentication classes and permission checks to your view
from rest_framework.permissions import IsAuthenticated,IsAuthenticatedOrReadOnly,IsAdminUser
from rest_framework_simplejwt.authentication import JWTAuthentication

# Create your views here.
class HelloNotesView(generics.GenericAPIView):
    def get(self,request):
        return Response(data={'message':'hello notes'},status=status.HTTP_200_OK)
    

##
class NoteCreateListView(generics.GenericAPIView): #we have class called NoteCreateListView who inherit from class generics.GenericAPIView
    #generics provides basic behavior for handling requests (GET, POST, etc.) and helps with features like pagination, authentication, and authorization. 
    #permission_classes=[IsAdminUser]#only the super user can access this method.
   #1-define the query set
    queryset = Note.objects.all()  # The queryset that will be used in the view, queryset define the set of attribute that the view will work with.
    #2-define the serializer clas
    serializer_class=serializers.UserNotesSerializer #This tells the view which serializer to use when converting
    def get(self,request):#here we define a get method
        #1-
        notes = self.get_queryset  # Use the queryset defined in the class, 
        #2-
        serializer=self.serializer_class(instance=notes,many=True)#This line creates an instance of the serializer (in this case, UserNotesSerializer).
        return Response(data=serializer.data,status=status.HTTP_200_OK)
    
    def post(self,request):
        #1-create an instance of the serializer with corresponding data 
        serializer=self.serializer_class(data=request.data)#this line create an instance of our serializer with the data of request to check validity of it 
        #2- check validity and authentication.
        if serializer.is_valid():
            if not request.user.is_authenticated:
                return Response(data={"error": "Authentication is required"}, status=status.HTTP_401_UNAUTHORIZED)
            #3-save it 
            serializer.save(user=request.user)# each note for a user so make sure to assign the user=request.user
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#####
class PostNote(generics.GenericAPIView):
    serializer_class=serializers.UserNotesSerializer
    # Apply authentication and permission classes
    authentication_classes = [JWTAuthentication]  # Use JWT for authentication
    permission_classes = [IsAuthenticatedOrReadOnly]  # Allow only authenticated users

    # def post(self,request):
    #     #1-create an instance of the serializer with corresponding data 
    #     serializer=self.serializer_class(data=request.data)#this line create an instance of our serializer with the data of request to check validity of it 
    #     #2- check validity and authentication.
    #     if serializer.is_valid():
    #         if not request.user.is_authenticated:
    #             return Response(data={"error": "Authentication is required"}, status=status.HTTP_401_UNAUTHORIZED)
    #         #3-save it 
    #         serializer.save(user=request.user)# each note for a user so make sure to assign the user=request.user
    #         return Response(data=serializer.data, status=status.HTTP_201_CREATED)
    #     return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    ##########
    def post(self, request):
        # 1. Create an instance of the serializer with the request data
        serializer = self.serializer_class(data=request.data)

        # 2. Check validity and authentication
        if serializer.is_valid():
            if not request.user.is_authenticated:
                return Response({
                    "statusCode": 401,
                    "message": "Authentication is required"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # 3. Save the note and assign the user from request
            serializer.save(user=request.user)

            # 4. Return a custom success response with a 201 status code
            return Response({
                "statusCode": 201,
                "message": "Note created successfully",
                "data": {
                    "_id": str(serializer.data['id']),
                    "category": serializer.data['category'],
                    "title": serializer.data['title'],
                    "text": serializer.data['text'],
                    "user": str(request.user.id)  # Ensure user ID is returned
                }
            }, status=status.HTTP_201_CREATED)

        # 5. If validation fails, return a custom error response
        return Response({
            "statusCode": 400,
            "message": "All fields are required",  # Customize the message for required fields
            "errors": serializer.errors  # Optionally include detailed errors
        }, status=status.HTTP_400_BAD_REQUEST)





class GetNote(generics.GenericAPIView):
    #2-define the serializer clas
    serializer_class=serializers.GetNoteSerializer

    # Apply authentication and permission classes
    authentication_classes = [JWTAuthentication]  # Use JWT for authentication
    permission_classes = [IsAuthenticatedOrReadOnly]  # Allow only authenticated users

    # def get(self,request,id): #This method handles GET requests and expects an id argument to fetch a specific Note object by its primary key.
    #     #1- we use built in method to get notes (it take model and the attrs we want who is the pk)
    #     note=get_object_or_404(Note,pk=id)#fetch data of a specified note by id.
    #     serializer=self.serializer_class(instance=note)
    #     return Response(data=serializer.data,status=status.HTTP_200_OK)
    #########################
    def get(self, request, id):
        try:
            # Check if the user is authenticated
            if not request.user.is_authenticated:
                return Response({
                    "statusCode": 401,
                    "message": "No token provided"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Retrieve the note by ID and serialize it
            note = get_object_or_404(Note, pk=id)
            serializer = self.serializer_class(note)

            # Customize the successful response structure
            return Response({
                "statusCode": 200,
                "message": "Notes fetched successfully",
                "data": {
                    "notes": [serializer.data]  # Wrap the note in a list as shown in the example
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Handle generic errors (optional)
            return Response({
                "statusCode": 500,
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

"""
in the previous method where we have get method we use queryset=Note.objects.all in which i get all data of the model 
note where here get_object_or_404 fetch specific data of a model by id.
"""

class UpdateNote(generics.GenericAPIView):
    serializer_class=serializers.UserNotesSerializer
    # Apply authentication and permission classes
    authentication_classes = [JWTAuthentication]  # Use JWT for authentication
    permission_classes = [IsAuthenticatedOrReadOnly]  # Allow only authenticated users

    
    # def put(self, request, id):
    #     # 1. Retrieve the existing note instance by ID
    #     note = get_object_or_404(Note, pk=id)
    
    #     # 2. Deserialize the incoming data and pass the existing instance to update it
    #     serializer = self.serializer_class(instance=note, data=request.data, partial=True)  # 'partial=True' allows for partial updates
    
    #     # 3. Validate the data
    #     if serializer.is_valid():
    #         # 4. Save the updated note instance
    #         serializer.save()
    #         return Response(data=serializer.data, status=status.HTTP_200_OK)
    
    #     # 5. Return an error response if validation fails
    #     return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    ###########
    def put(self, request, id):
        # 1. Retrieve the existing note instance by ID and check if the user is authorized to update it
        note = get_object_or_404(Note, pk=id, user=request.user)  # Ensure note exists and belongs to the user
        
        # 2. Deserialize the incoming data and pass the existing instance to update it
        serializer = self.serializer_class(instance=note, data=request.data, partial=True)  # 'partial=True' allows for partial updates
        
        # 3. Validate the data
        if serializer.is_valid():
            # 4. Save the updated note instance
            serializer.save()

            # 5. Return a custom success response with a 200 status code
            return Response({
                "statusCode": 200,
                "message": "Note updated successfully",
                "data": {
                    "_id": str(serializer.data['id']),
                    "category": serializer.data['category'],
                    "title": serializer.data['title'],
                    "text": serializer.data['text'],
                    "user": str(request.user.id)  # Return the user ID
                }
            }, status=status.HTTP_200_OK)

        # 6. Return an error response if validation fails
        return Response({
            "statusCode": 400,
            "message": "Invalid data provided",
            "errors": serializer.errors  # Optionally provide detailed errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def handle_exception(self, exc):
        if isinstance(exc, Http404):
            return Response({
                "statusCode": 404,
                "message": "Note not found or not authorized to update"
            }, status=status.HTTP_404_NOT_FOUND)
        return super().handle_exception(exc)
    
class DeleteNote(generics.GenericAPIView):
    # Apply authentication and permission classes
    authentication_classes = [JWTAuthentication]  # Use JWT for authentication
    permission_classes = [IsAuthenticatedOrReadOnly]  # Allow only authenticated users

    def delete(self,request,id):
        note = get_object_or_404(Note, pk=id)
        note.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


####################### get all notes 
class GetAllNotes(generics.GenericAPIView):
    # Define the serializer class
    serializer_class = serializers.GetNoteSerializer

    # Apply authentication and permission classes
    authentication_classes = [JWTAuthentication]  # Use JWT for authentication
    permission_classes = [IsAuthenticatedOrReadOnly]  # Allow only authenticated users

    def get(self, request):
        try:
            # Check if the user is authenticated
            if not request.user.is_authenticated:
                return Response({
                    "statusCode": 401,
                    "message": "No token provided"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Retrieve all notes and serialize them
            notes = Note.objects.all()  # Fetch all notes from the database
            serializer = self.serializer_class(notes, many=True)  # Set many=True to handle multiple objects

            # Customize the successful response structure
            return Response({
                "statusCode": 200,
                "message": "Notes fetched successfully",
                "data": {
                    "notes": serializer.data  # Return all the notes
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Handle generic errors (optional)
            return Response({
                "statusCode": 500,
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

